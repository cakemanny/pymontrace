#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "attacher.h"

/*
 * For supporting a small number of background or worker threads, not
 * something like a threaded http server.
 */
enum { MAX_THREADS = 16 };

#define ATTACH_ERR_MSG  "Error occurred installing/uninstalling probes."
#define UNKNOWN_STATE_ERR_MSG  \
    (ATTACH_ERR_MSG " Target process may be in an unknown state.")

// Module state
typedef struct {
    PyObject *AttachError_Type;
    PyObject *UnknownStateError_Type;
    PyObject *InterruptedError_Type;
} attacher_state;


static void
set_python_error(PyObject *module, int err)
{
    attacher_state *state = PyModule_GetState(module);
    if (state == NULL) {
        // The calling code will return null for us
        return;
    }
    PyObject* type;
    char* msg;
    switch (err) {
        case ATT_UNKNOWN_STATE:
            type = state->UnknownStateError_Type;
            msg = UNKNOWN_STATE_ERR_MSG;
            break;
        case ATT_INTERRUPTED:
            type = state->InterruptedError_Type;
            msg = ATTACH_ERR_MSG;
        default:
            type = state->AttachError_Type;
            msg = ATTACH_ERR_MSG;
            break;
    }
    PyErr_SetString(type, msg);
}

static PyObject *
attacher_attach_and_exec(PyObject *module, PyObject *args)
{
    int pid;
    const char *command;
    int err;

    if (!PyArg_ParseTuple(args, "is:attach_and_exec", &pid, &command)) {
        return NULL;
    }
    err = attach_and_execute(pid, command);
    if (err != 0) {
        set_python_error(module, err);
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
attacher_exec_in_threads(PyObject *module, PyObject *args)
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
        set_python_error(module, err);
    }

    Py_RETURN_NONE;
}

static PyMethodDef attacher_methods[] = {
    {"attach_and_exec",  attacher_attach_and_exec, METH_VARARGS,
     "attach_and_exec(pid: int, python_code: str)"},
    {"exec_in_threads",  attacher_exec_in_threads, METH_VARARGS,
     "exec_in_threads(pid: int, tids: list[int], python_code: str)"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};


// The module itself

PyDoc_STRVAR(module_doc, "\
Platform specific code to attach to running python processes and execute\n\
code to bootstrap pymontrace\n\
");

static int
attacher_modexec(PyObject *m)
{
    attacher_state *state = PyModule_GetState(m);

#define ADD_EXC(MOD, NAME, VAR, BASE) do {                                    \
    state->VAR = PyErr_NewException("pymontrace.attacher." NAME, BASE, NULL); \
    if (state->VAR == NULL) {                                                 \
        return -1;                                                            \
    }                                                                         \
    if (PyModule_AddType(m, (PyTypeObject*)state->VAR) < 0) {                 \
        return -1;                                                            \
    }                                                                         \
} while (0)

    ADD_EXC(m, "AttachError", AttachError_Type, NULL);
    ADD_EXC(m, "UnknownStateError", UnknownStateError_Type, state->AttachError_Type);
    ADD_EXC(m, "InterruptedError", InterruptedError_Type, state->AttachError_Type);

#undef ADD_EXC


    return 0;
}

static PyModuleDef_Slot attacher_slots[] = {
    {Py_mod_exec, attacher_modexec},
    {0, NULL}
};

static int
attacher_traverse(PyObject *module, visitproc visit, void *arg)
{
    attacher_state *state = PyModule_GetState(module);
    Py_VISIT(state->AttachError_Type);
    Py_VISIT(state->UnknownStateError_Type);
    Py_VISIT(state->InterruptedError_Type);
    return 0;
}

static int
attacher_clear(PyObject *module)
{
    attacher_state *state = PyModule_GetState(module);
    Py_CLEAR(state->InterruptedError_Type);
    Py_CLEAR(state->UnknownStateError_Type);
    // We clear this one last because it's the base type
    Py_CLEAR(state->AttachError_Type);
    return 0;
}

static struct PyModuleDef attachermodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "pymontrace.attacher",
    .m_doc = module_doc,
    .m_size = sizeof(attacher_state),
    .m_methods = attacher_methods,
    .m_slots = attacher_slots,
    .m_traverse = attacher_traverse,
    .m_clear = attacher_clear,
    /* m_free is not necessary here: xx_clear clears all references,
     * and the module state is deallocated along with the module.
     */
};


PyMODINIT_FUNC
PyInit_attacher(void)
{
    return PyModuleDef_Init(&attachermodule);
}
