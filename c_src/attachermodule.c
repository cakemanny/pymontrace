#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "attacher.h"


static PyObject *
attacher_attach_and_exec(PyObject *self, PyObject *args)
{
    int pid;
    const char *command;
    int err;

    if (!PyArg_ParseTuple(args, "is", &pid, &command)) {
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

static PyMethodDef AttacherMethods[] = {
    {"attach_and_exec",  attacher_attach_and_exec, METH_VARARGS,
     "attach_and_exec(pid: int, python_code: str)"},
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
