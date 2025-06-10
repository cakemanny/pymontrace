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
    _Atomic unsigned long epoch;
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
    PyObject *AggBuffer_Type;    // AggBuffer class

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

    unsigned long ctr = 0;
    if (!atomic_compare_exchange_strong_explicit(&hdr->counter, &ctr, 1 + ctr,
                memory_order_acq_rel, memory_order_acquire)) {
        // Buffer has already been initialised.
        return self;
    }

    /* start at 2 so that the second buffer (starting at epoch 1) is invalid
     * to start */
    atomic_store_explicit(&hdr->epoch, 2, memory_order_relaxed);
    hdr->bufs[0].start = sizeof(struct mapping_header);
    hdr->bufs[0].position = hdr->bufs[0].start;
    hdr->bufs[0].limit = len / 2;
    hdr->bufs[0].epoch = 2;
    hdr->bufs[1].start = hdr->bufs[0].limit;
    hdr->bufs[1].position = hdr->bufs[1].start;
    hdr->bufs[1].limit = len;
    hdr->bufs[1].epoch = 1;

    // Make writes visible
    atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);

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
                memory_order_acq_rel, memory_order_acquire)) {
        PyErr_SetString(PyExc_RuntimeError, "other writer accessing buffer");
        return NULL;
    }

    // relaxed is fine here because the read is guarded by the lock of the
    // counter
    int which_buffer = 1 & atomic_load_explicit(&hdr->epoch, memory_order_relaxed);
    __auto_type buf = &hdr->bufs[which_buffer];
    uint32_t space = buf->limit - buf->position;

    if (space < data_len) {
        // switch
        atomic_fetch_add_explicit(&hdr->epoch, 1, memory_order_relaxed);
        which_buffer ^= 1;
        buf = &hdr->bufs[which_buffer];
        assert(data_len < (buf->limit - buf->start));
        buf->position = buf->start + data_len;
        buf->epoch += 2;
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
    char* out_buf = NULL;
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
        if (self->epoch > buf->epoch) {
            PySys_FormatStderr("self->epoch: %lu\n", self->epoch);
            PySys_FormatStderr("buf->epoch: %"PRIu64"\n", buf->epoch);
        }
        assert(self->epoch <= buf->epoch);
        if (self->epoch != buf->epoch) {
            PySys_FormatStderr("WARN: dropped buffer(s)\n");
            // FIXME: probably we should check it was a clean read before
            // bumping our epoch?
            self->epoch = buf->epoch - 1;
            self->mark = 0;
            continue;
        }
        uint32_t start = buf->start + self->mark;
        uint32_t length = buf->position - start;
        if (length == 0) {
            // relaxed is fine here as we have the fence. (in fact epoch is
            // only atomic for AggBuffer)
            unsigned long hdr_epoch =
                atomic_load_explicit(&hdr->epoch, memory_order_relaxed);
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
            PyMem_Free(out_buf); // in case we saw a length in a previous loop
            char empty_buf[1] = {};
            return Py_BuildValue("y#", empty_buf, 0);
        }

        long offset = start;
        if (length > 0 && length <= self->len / 2) {
            void* resized = PyMem_Realloc(out_buf, length);
            if (resized == NULL) {
                PyMem_Free(out_buf);
                PyErr_SetNone(PyExc_MemoryError);
                return NULL;
            }
            out_buf = resized;

            memcpy(out_buf, self->data + offset, length);
            out_len = length;
        } else {
            PySys_FormatStderr("WARN: bad read length\n");
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
            PyObject* rv = Py_BuildValue("y#", out_buf, out_len);
            PyMem_Free(out_buf);
            return rv;
        }
    }

    /*
     * Perhaps it's worth checking if the counter incremented at all
     * or if we suspect the target died with the lock held...
     */

    // failed
    PyErr_SetString(PyExc_RuntimeError, "failed to get a clean read");
    PyMem_Free(out_buf);
    return NULL;
}

static PyMethodDef TraceBuffer_methods[] = {
    {"write", TraceBuffer_write, METH_VARARGS,
     PyDoc_STR("write(data: bytes) -> None")},
    {"read", TraceBuffer_read, METH_VARARGS,
     PyDoc_STR("read() -> bytes")},
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

/* AggBuffer objects */

// Instance state
typedef struct {
    PyObject_HEAD
    int fd;
    void* data; // The mmapped mappings.
    size_t len; // The length of the mapping.

} AggBufferObject;

#define AggBufferObject_CAST(op)  ((AggBufferObject *)(op))

static AggBufferObject *
newAggBufferObject(PyObject *module, int fd, const char* name)
{
    tracebuffer_state *state = PyModule_GetState(module);
    if (state == NULL) {
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

    AggBufferObject *self;
    self = PyObject_GC_New(AggBufferObject, (PyTypeObject*)state->AggBuffer_Type);
    if (self == NULL) {
        return NULL;
    }

    self->fd = fd;
    self->data = mapped;
    self->len = len;

    struct mapping_header* hdr = self->data;

    unsigned long ctr = 0;
    if (!atomic_compare_exchange_strong_explicit(&hdr->counter, &ctr, 1 + ctr,
                memory_order_acq_rel, memory_order_acquire)) {
        // Buffer has already been initialised.
        return self;
    }

    /* start at 2 so that the second buffer (starting at epoch 1) is invalid
     * to start */
    // relaxed is fine here as the mapping hasn't been shared yet
    atomic_store_explicit(&hdr->epoch, 2, memory_order_relaxed);
    if (name != NULL) {
        strncpy(hdr->bufname, name, sizeof(hdr->bufname) - 1);
        hdr->bufname[sizeof(hdr->bufname) - 1] = '\0';
    }
    hdr->bufs[0].start = sizeof(struct mapping_header);
    hdr->bufs[0].position = hdr->bufs[0].start;
    hdr->bufs[0].limit = len / 2;
    hdr->bufs[0].epoch = 2;
    hdr->bufs[1].start = hdr->bufs[0].limit;
    hdr->bufs[1].position = hdr->bufs[1].start;
    hdr->bufs[1].limit = len;
    hdr->bufs[1].epoch = 1;

    // Make writes visible
    atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);

    return self;
}

/* AggBuffer finalization */

static int
AggBuffer_traverse(PyObject *op, visitproc visit, void *arg)
{
    // Visit the type
    Py_VISIT(Py_TYPE(op));

    // Visit the attribute dict
    AggBufferObject *self = AggBufferObject_CAST(op);
    if(self) {}
    return 0;
}

static int
AggBuffer_clear(PyObject *op)
{
    AggBufferObject *self = AggBufferObject_CAST(op);
    if(self) {}
    return 0;
}

static void
AggBuffer_finalize(PyObject *op)
{
    AggBufferObject *self = AggBufferObject_CAST(op);
    if(self) {}
}

static void
AggBuffer_dealloc(PyObject *op)
{

    PyObject_GC_UnTrack(op);
    AggBuffer_finalize(op);
    PyTypeObject *tp = Py_TYPE(op);

    AggBufferObject *self = AggBufferObject_CAST(op);

    int err;
    Py_BEGIN_ALLOW_THREADS
    err = munmap(self->data, self->len);
    Py_END_ALLOW_THREADS
    if (err == -1) {
        // The deallocator must not change exceptions... so.
        // Look into PyErr_WriteUnraisable
#ifndef NDEBUG
        perror("_tracebuffer.AggBuffer: munmap");
#endif
    }

    freefunc free = PyType_GetSlot(tp, Py_tp_free);
    free(self);
    Py_DECREF(tp);
}

/* AggBuffer methods */

static PyObject *
AggBuffer_read(PyObject *op, PyObject *args)
{
    AggBufferObject *self = AggBufferObject_CAST(op);

    unsigned long epoch;
    Py_ssize_t offset;
    Py_ssize_t size;

    if (!PyArg_ParseTuple(args, "knn:read", &epoch, &offset, &size)) {
        return NULL;
    }

    int which_buffer = epoch & 1;
    struct mapping_header* hdr = self->data;

    __auto_type buf = &hdr->bufs[which_buffer];
    if (buf->epoch != epoch) {
        PyErr_Format(PyExc_RuntimeError,
                "buffer has epoch %"PRIu64", expected %lu", buf->epoch, epoch);
        return NULL;
    }

    if (offset < buf->start || offset + size > buf->limit) {
        PyErr_SetString(PyExc_ValueError, "offset/+size out of bounds");
        return NULL;
    }

    return Py_BuildValue("y#", self->data + offset, size);
}

static PyObject *
AggBuffer_write(PyObject *op, PyObject *args)
{
    AggBufferObject *self = AggBufferObject_CAST(op);

    unsigned long epoch;
    const char* data;
    ssize_t data_len;

    if (!PyArg_ParseTuple(args, "ky#:write", &epoch, &data, &data_len)) {
        return NULL;
    }
    assert(data_len >= 0);

    int which_buffer = epoch & 1;

    struct mapping_header* hdr = self->data;

    unsigned long ctr = atomic_load_explicit(&hdr->counter, memory_order_acquire);

    if (ctr & 1) {
        // Shouldn't happen, as there is external locking
        PyErr_SetString(PyExc_RuntimeError, "buffer is busy.");
        return NULL;
    }

    // Lock
    if (!atomic_compare_exchange_strong_explicit(&hdr->counter, &ctr, 1 + ctr,
                memory_order_acq_rel, memory_order_acquire)) {
        PyErr_SetString(PyExc_RuntimeError, "other writer accessing buffer");
        return NULL;
    }

    __auto_type buf = &hdr->bufs[which_buffer];
    if (buf->epoch != epoch) {
        atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);
        PyErr_Format(PyExc_RuntimeError,
                "buffer has epoch %"PRIu64", expected %lu", buf->epoch, epoch);
        return NULL;
    }

    uint32_t space = buf->limit - buf->position;
    if (space < data_len) {
        // TODO: increment some drop count
        // Unlock
        atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);
        PyErr_SetString(PyExc_MemoryError, "current buffer is full");
        return NULL;
    }

    memcpy(self->data + buf->position, data, data_len);
    buf->position += data_len;

    // Unlock
    atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);
    return Py_BuildValue("nn", (Py_ssize_t)(buf->position - data_len), data_len);
}

static PyObject *
AggBuffer_update(PyObject *op, PyObject *args)
{
    AggBufferObject *self = AggBufferObject_CAST(op);

    unsigned long epoch;
    const char* data;
    ssize_t data_len;
    Py_ssize_t offset;
    Py_ssize_t size;

    if (!PyArg_ParseTuple(args, "ky#nn:update", &epoch, &data, &data_len,
                &offset, &size)) {
        return NULL;
    }
    assert(data_len >= 0);
    if (size != data_len) {
        PyErr_SetString(PyExc_ValueError, "size changed, cannot update");
        return NULL;
    }

    int which_buffer = epoch & 1;

    struct mapping_header* hdr = self->data;

    unsigned long ctr = atomic_load_explicit(&hdr->counter, memory_order_acquire);
    if (ctr & 1) {
        PyErr_SetString(PyExc_RuntimeError, "buffer is busy.");
        return NULL;
    }

    // Lock
    if (!atomic_compare_exchange_strong_explicit(&hdr->counter, &ctr, 1 + ctr,
                memory_order_acq_rel, memory_order_acquire)) {
        PyErr_SetString(PyExc_RuntimeError, "other writer accessing buffer");
        return NULL;
    }

    __auto_type buf = &hdr->bufs[which_buffer];
    if (buf->epoch != epoch) {
        // Unlock
        atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);
        PyErr_Format(PyExc_RuntimeError,
                "buffer has epoch %"PRIu64", expected %lu", buf->epoch, epoch);
        return NULL;
    }
    if (offset < buf->start || offset + size > buf->limit) {
        // Unlock
        atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);
        PyErr_SetString(PyExc_ValueError, "offset/+size out of bounds");
        return NULL;
    }

    memcpy(self->data + offset, data, data_len);

    // Unlock
    atomic_fetch_add_explicit(&hdr->counter, 1, memory_order_release);
    return Py_BuildValue("nn", offset, data_len);
}

static PyObject *
AggBuffer_readall(PyObject *op, PyObject *args)
{
    AggBufferObject *self = AggBufferObject_CAST(op);

    unsigned long epoch;

    if (!PyArg_ParseTuple(args, "k:readall", &epoch)) {
        return NULL;
    }

    int which_buffer = epoch & 1;
    struct mapping_header* hdr = self->data;

    // We want to see the latest writes to the buffer header.
    // This is only sufficient for as long as we
    // 1. only read after detaching OR
    // 2. only if already having picked the inactive buffer.
    atomic_load_explicit(&hdr->counter, memory_order_acquire);

    __auto_type buf = &hdr->bufs[which_buffer];
    if (buf->epoch != epoch) {
        PyErr_Format(PyExc_RuntimeError,
                "buffer has epoch %"PRIu64", expected %lu", buf->epoch, epoch);
        return NULL;
    }

    return Py_BuildValue("y#", self->data + buf->start,
            (Py_ssize_t)(buf->position - buf->start));
}

static PyMethodDef AggBuffer_methods[] = {
    {"read", AggBuffer_read, METH_VARARGS,
     PyDoc_STR("read(epoch: int, offset: int, size: int) -> bytes")},
    {"write", AggBuffer_write, METH_VARARGS,
     PyDoc_STR("write(epoch: int, kvp_data: bytes) -> (offset: int, size: int)")},
    {"update", AggBuffer_update, METH_VARARGS,
     PyDoc_STR("write(epoch: int, kvp_data: bytes, offset: int, oldsize: int) "
               "-> (offset: int, size: int)")},
    {"readall", AggBuffer_readall, METH_VARARGS,
     PyDoc_STR("readall(epoch: int) -> str")},
    {NULL, NULL, 0, NULL}           /* sentinel */
};


static PyObject *
AggBuffer_get_epoch(PyObject *op, void *Py_UNUSED(closure))
{
    AggBufferObject *self = AggBufferObject_CAST(op);

    struct mapping_header* hdr = self->data;

    unsigned long epoch;
    /*
     * Acquire semantics here because this precedes reading the buffer header
     * which may have been updated by the tracer.
     */
    epoch = atomic_load_explicit(&hdr->epoch, memory_order_acquire);

    return PyLong_FromUnsignedLong(epoch);
}

static PyObject *
AggBuffer_get_name(PyObject *op, void *Py_UNUSED(closure))
{
    AggBufferObject *self = AggBufferObject_CAST(op);

    struct mapping_header* hdr = self->data;

    return Py_BuildValue("s", hdr->bufname);
}

/* AggBuffer type definition */

PyDoc_STRVAR(AggBuffer_doc,
        "A buffer for writing aggregation data, backed by a shared mmap file.");

static PyGetSetDef AggBuffer_getsetlist[] = {
    {"epoch", AggBuffer_get_epoch, NULL, NULL},
    {"name", AggBuffer_get_name, NULL, NULL},
    {NULL},
};

static PyType_Slot AggBuffer_Type_slots[] = {
    {Py_tp_doc, (char *)AggBuffer_doc},
    {Py_tp_traverse, AggBuffer_traverse},
    {Py_tp_clear, AggBuffer_clear},
    {Py_tp_finalize, AggBuffer_finalize},
    {Py_tp_dealloc, AggBuffer_dealloc},
    {Py_tp_methods, AggBuffer_methods},
    {Py_tp_getset, AggBuffer_getsetlist},
    {0, 0},  /* sentinel */
};

static PyType_Spec AggBuffer_Type_spec = {
    .name = "pymontrace._tracebuffer.AggBuffer",
    .basicsize = sizeof(AggBufferObject),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .slots = AggBuffer_Type_slots,
};

/* Module Methods */

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

static PyObject *
tracebuffer_create_aggbuffer(PyObject *module, PyObject *args)
{
    int fd;
    const char* name;
    ssize_t name_len;
    AggBufferObject* rv;

    if (!PyArg_ParseTuple(args, "is#:create_agg_buffer", &fd, &name,
                &name_len)) {
        return NULL;
    }
    struct mapping_header *hdr;
    if ((size_t)name_len > sizeof(hdr->bufname) - 1) {
        PyErr_SetString(PyExc_ValueError, "buffer name too long: max 31");
        return NULL;
    }

    rv = newAggBufferObject(module, fd, name);
    if (rv == NULL) {
        return NULL;
    }
    return (PyObject *)rv;
}

static PyObject *
tracebuffer_open_aggbuffer(PyObject *module, PyObject *args)
{
    int fd;
    AggBufferObject* rv;

    if (!PyArg_ParseTuple(args, "i:create_agg_buffer", &fd)) {
        return NULL;
    }

    rv = newAggBufferObject(module, fd, NULL);
    if (rv == NULL) {
        return NULL;
    }
    return (PyObject *)rv;
}


PyDoc_STRVAR(create__doc__, "\
create(file_descriptor: int)");

static PyMethodDef tracebuffer_methods[] = {
    {"create", tracebuffer_create, METH_VARARGS,
     create__doc__},
    {"create_agg_buffer", tracebuffer_create_aggbuffer, METH_VARARGS,
     PyDoc_STR("create_agg_buffer(fd: int, name: bytes) -> AggBuffer")},
    {"open_agg_buffer", tracebuffer_open_aggbuffer, METH_VARARGS,
     PyDoc_STR("open_agg_buffer(fd: int) -> AggBuffer")},
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

    state->AggBuffer_Type =
        PyType_FromModuleAndSpec(m, &AggBuffer_Type_spec, NULL);
    if (state->AggBuffer_Type == NULL) {
        return -1;
    }
    if (PyModule_AddType(m, (PyTypeObject*)state->AggBuffer_Type) < 0) {
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
    Py_VISIT(state->AggBuffer_Type);

    return 0;
}

static int
tracebuffer_clear(PyObject *module)
{
    tracebuffer_state *state = PyModule_GetState(module);
    Py_CLEAR(state->TraceBuffer_Type);
    Py_CLEAR(state->AggBuffer_Type);
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
