#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x03090000
#include <Python.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <sched.h>

// Ensure assertions are not compiled out.
#ifdef NDEBUG
#undef NDEBUG
#include <assert.h>
#define NDEBUG
#else
#include <assert.h>
#endif

/*
 * The implementation must use atomics i.e. be lock free as going to
 * sleep on a cross-process mutex
 */
#if (ATOMIC_LONG_LOCK_FREE != 2) || (ATOMIC_LLONG_LOCK_FREE != 2)
#error "Platform does not guarantee required atomic operations."
#endif

#if defined(__aarch64__) || defined(__arm64__)
#   define cpu_relax()  asm volatile("yield" ::: "memory")
#elif defined(__x86_64__) || defined(__riscv)
// https://www.felixcloutier.com/x86/pause
// https://github.com/riscv/riscv-isa-manual/blob/main/src/zihintpause.adoc
#   define cpu_relax()  asm volatile("pause")
#else
#   define cpu_relax()  ;;
#endif

// The structure that lives at the head of our mapping
struct mapping_header {
    _Atomic unsigned long counter;

    long msg_offset;
    long msg_size;
};


// Module state
typedef struct {
    PyObject *MapBuffer_Type;    // MapBuffer class
                           //
    /*
     * Could contains something like a linked list to all the instances?
     */
} mapbuffer_state;

/* MapBuffer objects */

// Instance state
typedef struct {
    PyObject_HEAD
    int fd;     // The fd backing the mapping. Not owned.
    void* data; // The mmapped mapping. Owned.
    size_t len; // The len of the mapping.

    int max_loops;  // PERF: A counter for benchmarking read
                    // efficiency/starvation
} MapBufferObject;

#define MapBufferObject_CAST(op)  ((MapBufferObject *)(op))

static MapBufferObject *
newMapBufferObject(PyObject *module, int fd, void* data, size_t len)
{
    mapbuffer_state *state = PyModule_GetState(module);
    if (state == NULL) {
        return NULL;
    }
    MapBufferObject *self;
    self = PyObject_GC_New(MapBufferObject, (PyTypeObject*)state->MapBuffer_Type);
    if (self == NULL) {
        return NULL;
    }

    self->fd = fd;
    self->data = data;
    self->len = len;
    self->max_loops = 0;

    return self;
}

/* MapBuffer finalization */

static int
MapBuffer_traverse(PyObject *op, visitproc visit, void *arg)
{
    // Visit the type
    Py_VISIT(Py_TYPE(op));

    // Visit the attribute dict
    MapBufferObject *self = MapBufferObject_CAST(op);
    if(self) {}
    return 0;
}

static int
MapBuffer_clear(PyObject *op)
{
    MapBufferObject *self = MapBufferObject_CAST(op);
    if(self) {}
    return 0;
}

static void
MapBuffer_finalize(PyObject *op)
{
    MapBufferObject *self = MapBufferObject_CAST(op);
    if(self) {}
}

static void
MapBuffer_dealloc(PyObject *op)
{

    PyObject_GC_UnTrack(op);
    MapBuffer_finalize(op);
    PyTypeObject *tp = Py_TYPE(op);

    MapBufferObject *self = MapBufferObject_CAST(op);

#if !defined(NDEBUG)
    fprintf(stderr, "mapbuffer: MAX_LOOPS = %d\n", self->max_loops);
#endif

    int err;
    Py_BEGIN_ALLOW_THREADS
    err = munmap(self->data, self->len);
    Py_END_ALLOW_THREADS
    if (err == -1) {
        // The deallocator must not change exceptions... so.
        // Look into PyErr_WriteUnraisable
#ifndef NDEBUG
        perror("_mapbuffer.MapBuffer: munmap");
#endif
    }

    freefunc free = PyType_GetSlot(tp, Py_tp_free);
    free(self);
    Py_DECREF(tp);
}

/* MapBuffer methods */

#define MAX_WRITE   1024

static PyObject *
MapBuffer_write(PyObject *op, PyObject *args)
{
    MapBufferObject *self = MapBufferObject_CAST(op);

    const char* data;
    ssize_t data_len;

    if (!PyArg_ParseTuple(args, "y#:write", &data, &data_len)) {
        return NULL;
    }
    assert(data_len >= 0);
    if (data_len == 0) {
        Py_RETURN_NONE;
    }
    if (data_len > MAX_WRITE) {
        PyErr_SetString(PyExc_ValueError, "too large: max size 1024");
        return NULL;
    }

    struct mapping_header* hdr = self->data;
    unsigned long ctr = atomic_load_explicit(&hdr->counter, memory_order_acquire);

    if (ctr & 1) {
        PyErr_SetString(PyExc_RuntimeError, "buffer is busy.");
        return NULL;
    }

    // Lock
    if (!atomic_compare_exchange_strong_explicit(&hdr->counter, &ctr, 1 + ctr,
                memory_order_acq_rel,
                // This could be relaxed because the msg_offset doesn't change
                // but in the future we may want to be able to read sth
                // that was written....
                memory_order_acquire)) {
        PyErr_SetString(PyExc_RuntimeError, "other writer accessing buffer");
        return NULL;
    }

    hdr->msg_offset = sizeof *hdr;
    static_assert(sizeof hdr->msg_size >= sizeof data_len, "msg_size is too small");
    hdr->msg_size = data_len;

    memcpy(self->data + hdr->msg_offset, data, data_len);

    // Unlock
    atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);

    Py_RETURN_NONE;
}


static PyObject *
MapBuffer_read(PyObject *op, PyObject *args)
{
    char buf[MAX_WRITE] = {};
    int out_len = 0;
    MapBufferObject *self = MapBufferObject_CAST(op);

    struct mapping_header* hdr = self->data;
    unsigned long ctr;

    for (int i = 0; i < 256; i++) {
        // The acquire says, ensure the subsequent read of the message is not
        // moved before this load.
        ctr = atomic_load_explicit(&hdr->counter, memory_order_acquire);
        if ((ctr & 1) != 0) {
            cpu_relax();
            if (((i + 1) & 63) == 0) {
                // In case the other process has come off cpu while writing,
                // we shall also come off cpu.
                sched_yield();
            }
            // TODO: Look into linux cpu_relax and rust's core::hint::spin_loop
            continue;
        }

        long size = hdr->msg_size;
        long offset = hdr->msg_offset;
        if (size > 0 && size <= MAX_WRITE) {
            assert(offset == sizeof(*hdr));
            memcpy(buf, self->data + offset, size);
            out_len = size;
        }

        // A fence so that the following counter read can't be moved before
        // the read of the data...
        atomic_thread_fence(memory_order_acquire);

        // This would ideally be memory_order_release, but that's not
        // possible.
        // Another possibility could be to do a fetch_add_(.., 2) ...
        unsigned long ctr2 = atomic_load_explicit(&hdr->counter,
                memory_order_relaxed);
        if (ctr == ctr2) {
            if (i > self->max_loops) self->max_loops = i;

            // clean read
            return Py_BuildValue("y#", buf, out_len);
        }
    }

    /*
     * Perhaps it's worth checking if the counter incremented at all
     * or if we suspect the target died with the lock held...
     */

    // failed
    PyErr_SetString(PyExc_RuntimeError, "failed to get a clean read");
    return NULL;
}

static PyMethodDef MapBuffer_methods[] = {
    {"write", MapBuffer_write, METH_VARARGS,
     PyDoc_STR("write(message: str) -> None")},
    {"read", MapBuffer_read, METH_VARARGS,
     PyDoc_STR("read() -> str")},
    {NULL, NULL, 0, NULL}           /* sentinel */
};

/* MapBuffer type definition */

PyDoc_STRVAR(MapBuffer_doc,
        "A wrapper around a shareable mmap");

static PyGetSetDef MapBuffer_getsetlist[] = {
    {NULL},
};

static PyType_Slot MapBuffer_Type_slots[] = {
    {Py_tp_doc, (char *)MapBuffer_doc},
    {Py_tp_traverse, MapBuffer_traverse},
    {Py_tp_clear, MapBuffer_clear},
    {Py_tp_finalize, MapBuffer_finalize},
    {Py_tp_dealloc, MapBuffer_dealloc},
    {Py_tp_methods, MapBuffer_methods},
    {Py_tp_getset, MapBuffer_getsetlist},
    {0, 0},  /* sentinel */
};

static PyType_Spec MapBuffer_Type_spec = {
    .name = "pymontrace._mapbuffer.MapBuffer",
    .basicsize = sizeof(MapBufferObject),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .slots = MapBuffer_Type_slots,
};


static PyObject *
mapbuffer_create(PyObject *module, PyObject *args)
{
    int fd;
    MapBufferObject* rv;

    if (!PyArg_ParseTuple(args, "i:create", &fd)) {
        return NULL;
    }

    // TODO: check file size?

    size_t len = 16384;
    void* mapped = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    rv = newMapBufferObject(module, fd, mapped, len);
    if (rv == NULL) {
        return NULL;
    }

    return (PyObject *)rv;
}


PyDoc_STRVAR(create__doc__, "\
create(file_descriptor: int)");

static PyMethodDef mapbuffer_methods[] = {
    {"create",  mapbuffer_create, METH_VARARGS,
     create__doc__},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

// The module itself

PyDoc_STRVAR(module_doc, "\
Lock-free interprocess data sharing.\n\
\n\
An mmap wrapper with synchronisation.\n\
");

static int
mapbuffer_modexec(PyObject *m)
{
    mapbuffer_state *state = PyModule_GetState(m);

    state->MapBuffer_Type =
        PyType_FromModuleAndSpec(m, &MapBuffer_Type_spec, NULL);
    if (state->MapBuffer_Type == NULL) {
        return -1;
    }
    if (PyModule_AddType(m, (PyTypeObject*)state->MapBuffer_Type) < 0) {
        return -1;
    }

    return 0;
}

static PyModuleDef_Slot mapbuffer_slots[] = {
    {Py_mod_exec, mapbuffer_modexec},
    {0, NULL}
};

static int
mapbuffer_traverse(PyObject *module, visitproc visit, void *arg)
{
    mapbuffer_state *state = PyModule_GetState(module);
    Py_VISIT(state->MapBuffer_Type);

    return 0;
}

static int
mapbuffer_clear(PyObject *module)
{
    mapbuffer_state *state = PyModule_GetState(module);
    Py_CLEAR(state->MapBuffer_Type);
    return 0;
}

static struct PyModuleDef mapbuffermodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "pymontrace._mapbuffer",
    .m_doc = module_doc,
    .m_size = sizeof(mapbuffer_state),
    .m_methods = mapbuffer_methods,
    .m_slots = mapbuffer_slots,
    .m_traverse = mapbuffer_traverse,
    .m_clear = mapbuffer_clear,
    .m_free = NULL,
};


PyMODINIT_FUNC
PyInit__mapbuffer(void)
{
    return PyModuleDef_Init(&mapbuffermodule);
}
