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
 * sleep on a cross-process mutex is unknown territory.
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
    unsigned long epoch;
    char bufname[32];

    struct {
        uint32_t start; /* offset from start of mapping */
        uint32_t position;  /* */
        uint32_t limit; /* end as offset from start of mapping */
        uint64_t epoch; /* even for first buffer, odd for second, matching
                           header for the active buffer */
    } bufs[2];
};


// Module state
typedef struct {
    PyObject *TraceBuffer_Type;    // TraceBuffer class
                           //
    /*
     * Could contains something like a linked list to all the instances?
     */
} tracebuffer_state;

/* TraceBuffer objects */

// Instance state
typedef struct {
    PyObject_HEAD
    int fd;     // The fd backing the mapping. Not owned.
    void* data; // The mmapped mapping. Owned.
    size_t len; // The len of the mapping.
    unsigned long epoch; // The epoch of the current buffer being read (reader)
    uint32_t mark; // The read position in the current buffer (reader)
                   // as an offset from its start.

    int max_loops;  // PERF: A counter for benchmarking read
                    // efficiency/starvation
} TraceBufferObject;

#define TraceBufferObject_CAST(op)  ((TraceBufferObject *)(op))

static TraceBufferObject *
newTraceBufferObject(PyObject *module, int fd, void* data, size_t len)
{
    tracebuffer_state *state = PyModule_GetState(module);
    if (state == NULL) {
        return NULL;
    }
    TraceBufferObject *self;
    self = PyObject_GC_New(TraceBufferObject, (PyTypeObject*)state->TraceBuffer_Type);
    if (self == NULL) {
        return NULL;
    }

    self->fd = fd;
    self->data = data;
    self->len = len;
    self->epoch = 2;
    self->mark = 0;
    self->max_loops = 0;

    struct mapping_header* hdr = self->data;
    /* start at 2 so that the second buffer (starting at epoch 1) is invalid
     * to start */
    hdr->counter = 0;
    hdr->epoch = 2;
    hdr->bufs[0].start = sizeof(struct mapping_header);
    hdr->bufs[0].position = hdr->bufs[0].start;
    hdr->bufs[0].limit = len / 2;
    hdr->bufs[0].epoch = 2;
    hdr->bufs[1].start = hdr->bufs[0].limit;
    hdr->bufs[1].position = hdr->bufs[1].start;
    hdr->bufs[1].limit = len;
    hdr->bufs[1].epoch = 1;

    return self;
}

/* TraceBuffer finalization */

static int
TraceBuffer_traverse(PyObject *op, visitproc visit, void *arg)
{
    // Visit the type
    Py_VISIT(Py_TYPE(op));

    // Visit the attribute dict
    TraceBufferObject *self = TraceBufferObject_CAST(op);
    if(self) {}
    return 0;
}

static int
TraceBuffer_clear(PyObject *op)
{
    TraceBufferObject *self = TraceBufferObject_CAST(op);
    if(self) {}
    return 0;
}

static void
TraceBuffer_finalize(PyObject *op)
{
    TraceBufferObject *self = TraceBufferObject_CAST(op);
    if(self) {}
}

static void
TraceBuffer_dealloc(PyObject *op)
{

    PyObject_GC_UnTrack(op);
    TraceBuffer_finalize(op);
    PyTypeObject *tp = Py_TYPE(op);

    TraceBufferObject *self = TraceBufferObject_CAST(op);

#if !defined(NDEBUG)
    fprintf(stderr, "tracebuffer: MAX_LOOPS = %d\n", self->max_loops);
#endif

    int err;
    Py_BEGIN_ALLOW_THREADS
    err = munmap(self->data, self->len);
    Py_END_ALLOW_THREADS
    if (err == -1) {
        // The deallocator must not change exceptions... so.
        // Look into PyErr_WriteUnraisable
#ifndef NDEBUG
        perror("_tracebuffer.TraceBuffer: munmap");
#endif
    }

    freefunc free = PyType_GetSlot(tp, Py_tp_free);
    free(self);
    Py_DECREF(tp);
}

/* TraceBuffer methods */

#define MAX_WRITE   1024

static PyObject *
TraceBuffer_write(PyObject *op, PyObject *args)
{
    TraceBufferObject *self = TraceBufferObject_CAST(op);

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
        // If we change this max write, then it must be based on the smallest
        // of the two buffer sizes.
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

    int which_buffer = hdr->epoch & 1;
    __auto_type buf = &hdr->bufs[which_buffer];
    uint32_t space = buf->limit - buf->position;

    if (space < data_len) {
        // switch
        hdr->epoch += 1;
        which_buffer ^= 1;
        buf = &hdr->bufs[which_buffer];
        assert(data_len < (buf->limit - buf->start));
        buf->position = buf->start + data_len;
        buf->epoch += 1;
    } else {
        buf->position += data_len;
    }

    memcpy(self->data + buf->position - data_len, data, data_len);

    // Unlock
    atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);

    Py_RETURN_NONE;
}


static PyObject *
TraceBuffer_read(PyObject *op, PyObject *args)
{
    char out_buf[MAX_WRITE] = {};
    int out_len = 0;
    TraceBufferObject *self = TraceBufferObject_CAST(op);

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
            continue;
        }

        int which_buffer = self->epoch & 1;
        __auto_type buf = &hdr->bufs[which_buffer];
        assert(self->epoch <= buf->epoch);
        if (self->epoch != buf->epoch) {
            // TODO: Is there some python function to write to the current
            // sys.stderr?
            fprintf(stderr, "WARN: dropped buffer\n");
            self->epoch += 1;
            self->mark = 0;
            continue;
        }
        uint32_t start = buf->start + self->mark;
        uint32_t length = buf->position - start;
        if (length == 0) {
            unsigned long hdr_epoch = hdr->epoch;
            // See below for full comments.
            atomic_thread_fence(memory_order_acquire);
            unsigned long ctr2 = atomic_load_explicit(&hdr->counter,
                    memory_order_relaxed);
            if (ctr != ctr2) {
                continue; // dirty read
            }
            if (self->epoch < hdr_epoch) {
                self->epoch += 1;
                self->mark = 0;
                continue;
            }
            // Nothing to read
            return Py_BuildValue("y#", out_buf, 0);
        }

        long offset = start;
        if (length > 0 && length <= MAX_WRITE) {
            memcpy(out_buf, self->data + offset, length);
            out_len = length;
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

            self->mark += length;
            // clean read
            return Py_BuildValue("y#", out_buf, out_len);
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

static PyMethodDef TraceBuffer_methods[] = {
    {"write", TraceBuffer_write, METH_VARARGS,
     PyDoc_STR("write(message: str) -> None")},
    {"read", TraceBuffer_read, METH_VARARGS,
     PyDoc_STR("read() -> str")},
    {NULL, NULL, 0, NULL}           /* sentinel */
};

/* TraceBuffer type definition */

PyDoc_STRVAR(TraceBuffer_doc,
        "A wrapper around a shareable mmap");

static PyGetSetDef TraceBuffer_getsetlist[] = {
    {NULL},
};

static PyType_Slot TraceBuffer_Type_slots[] = {
    {Py_tp_doc, (char *)TraceBuffer_doc},
    {Py_tp_traverse, TraceBuffer_traverse},
    {Py_tp_clear, TraceBuffer_clear},
    {Py_tp_finalize, TraceBuffer_finalize},
    {Py_tp_dealloc, TraceBuffer_dealloc},
    {Py_tp_methods, TraceBuffer_methods},
    {Py_tp_getset, TraceBuffer_getsetlist},
    {0, 0},  /* sentinel */
};

static PyType_Spec TraceBuffer_Type_spec = {
    .name = "pymontrace._tracebuffer.TraceBuffer",
    .basicsize = sizeof(TraceBufferObject),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .slots = TraceBuffer_Type_slots,
};


static PyObject *
tracebuffer_create(PyObject *module, PyObject *args)
{
    int fd;
    TraceBufferObject* rv;

    if (!PyArg_ParseTuple(args, "i:create", &fd)) {
        return NULL;
    }

    struct stat statbuf;
    if (-1 == fstat(fd, &statbuf)) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    size_t len = (size_t)statbuf.st_size;
    void* mapped = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    rv = newTraceBufferObject(module, fd, mapped, len);
    if (rv == NULL) {
        return NULL;
    }

    return (PyObject *)rv;
}


PyDoc_STRVAR(create__doc__, "\
create(file_descriptor: int)");

static PyMethodDef tracebuffer_methods[] = {
    {"create",  tracebuffer_create, METH_VARARGS,
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
tracebuffer_modexec(PyObject *m)
{
    tracebuffer_state *state = PyModule_GetState(m);

    state->TraceBuffer_Type =
        PyType_FromModuleAndSpec(m, &TraceBuffer_Type_spec, NULL);
    if (state->TraceBuffer_Type == NULL) {
        return -1;
    }
    if (PyModule_AddType(m, (PyTypeObject*)state->TraceBuffer_Type) < 0) {
        return -1;
    }

    return 0;
}

static PyModuleDef_Slot tracebuffer_slots[] = {
    {Py_mod_exec, tracebuffer_modexec},
    {0, NULL}
};

static int
tracebuffer_traverse(PyObject *module, visitproc visit, void *arg)
{
    tracebuffer_state *state = PyModule_GetState(module);
    Py_VISIT(state->TraceBuffer_Type);

    return 0;
}

static int
tracebuffer_clear(PyObject *module)
{
    tracebuffer_state *state = PyModule_GetState(module);
    Py_CLEAR(state->TraceBuffer_Type);
    return 0;
}

static struct PyModuleDef tracebuffermodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "pymontrace._tracebuffer",
    .m_doc = module_doc,
    .m_size = sizeof(tracebuffer_state),
    .m_methods = tracebuffer_methods,
    .m_slots = tracebuffer_slots,
    .m_traverse = tracebuffer_traverse,
    .m_clear = tracebuffer_clear,
    .m_free = NULL,
};


PyMODINIT_FUNC
PyInit__tracebuffer(void)
{
    return PyModuleDef_Init(&tracebuffermodule);
}
