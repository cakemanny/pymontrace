#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "attacher.h"

/*
 * For supporting a small number of background or worker threads, not
 * something like a threaded http server.
 */
enum { MAX_THREADS = 16 };

static PyObject *
attacher_attach_and_exec(PyObject *self, PyObject *args)
{
    int pid;
    const char *command;
    int err;

    if (!PyArg_ParseTuple(args, "is:attach_and_exec", &pid, &command)) {
        return NULL;
    }
    err = attach_and_execute(pid, command);
    if (err != 0) {
        char* msg = (err == ATT_UNKNOWN_STATE)
            ? "Error occurred installing/uninstalling probes. "
                "Target process may be in an unknown state."
            : "Error occurred installing/uninstalling probes.";
        PyErr_SetString(PyExc_RuntimeError, msg);
        return NULL;
    }

    Py_RETURN_NONE;
}

static int
convert_tids(PyObject *arg, uint64_t* tids)
{
    if (!PySequence_Check(arg)) {
        PyErr_SetString(PyExc_TypeError, "'tids' must be sequence of ints");
        return 0;
    }
    ssize_t len = PySequence_Length(arg);
    if (len > MAX_THREADS) {
        PyErr_SetString(PyExc_ValueError,
                "Number of tids cannot exceed 16" /* MAX_THREADS */ );
        return 0;
    }
    for (int i = 0; i < len; i++) {
        PyObject* item = PySequence_GetItem(arg, i);
        if (!PyLong_Check(item)) {
            Py_DECREF(item);
            PyErr_SetString(PyExc_TypeError, "'tids' must be sequence of ints");
            return 0;
        }
        tids[i] = PyLong_AsUnsignedLongLong(item);
        if (tids[i] == ((unsigned long long)-1)) {
            Py_DECREF(item);
            return 0;
        }
        Py_DECREF(item);
    }
    return 1;
}

static PyObject *
attacher_exec_in_threads(PyObject *self, PyObject *args)
{
    int pid;
    const char *command;
    int err;
    uint64_t tids[MAX_THREADS] = {};

    if (!PyArg_ParseTuple(args, "iO&s:exec_in_threads", &pid, &convert_tids,
                tids, &command)) {
        return NULL;
    }

    int count_tids = 0;
    for (int i = 0; i < MAX_THREADS; i++) {
        if (tids[i] != 0) { count_tids += 1; }
    }

    Py_BEGIN_ALLOW_THREADS
    err = execute_in_threads(pid, tids, count_tids, command);
    Py_END_ALLOW_THREADS
    if (err < 0) {
        PyErr_SetNone(PyExc_NotImplementedError);
        return NULL;
    }

    err = 0;
    if (err != 0) {
        char* msg = (err == ATT_UNKNOWN_STATE)
            ? "Error occurred installing/uninstalling probes. "
                "Target process may be in an unknown state."
            : "Error occurred installing/uninstalling probes.";
        PyErr_SetString(PyExc_RuntimeError, msg);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyMethodDef AttacherMethods[] = {
    {"attach_and_exec",  attacher_attach_and_exec, METH_VARARGS,
     "attach_and_exec(pid: int, python_code: str)"},
    {"exec_in_threads",  attacher_exec_in_threads, METH_VARARGS,
     "exec_in_threads(pid: int, tids: list[int], python_code: str)"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};


static struct PyModuleDef attachermodule = {
    PyModuleDef_HEAD_INIT,
    "pymontrace.attacher",   /* name of module */
    "\
Platform specific code to attach to running python processes and execute\n\
code to bootstrap pymontrace\n\
", /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    AttacherMethods
};


PyMODINIT_FUNC
PyInit_attacher(void)
{
    return PyModule_Create(&attachermodule);
}
