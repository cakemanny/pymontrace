#include <inttypes.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>

#include <dispatch/dispatch.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach/mach_param.h>

#include <assert.h>

#include "attacher.h"

#if !defined(__arm64__) && !defined(__x86_64__)
#error "Platform not yet supported"
#endif

const bool debug = false;

#define NELEMS(A) ((sizeof A) / sizeof A[0])

// this does not seem to be called as often as I'd hoped
// maybe drop_gil is better...
//#define SAFE_POINT "PyErr_CheckSignals"
#define SAFE_POINT  "PyEval_SaveThread"

#define PYTHON_SO_BASENAME  "Python"

// this is what clang gives for __builtin_debugtrap()
//	brk	#0xf000
#if defined(__arm64__)
#define DEBUG_TRAP_INSTR    ((uint32_t)0xd43e0000)
#elif defined(__x86_64__)
#define DEBUG_TRAP_INSTR    ((uint8_t)0xcc)
#endif

// Note we don't use atomic routines to set this when setting it
// just before using the semaphore.
static _Atomic int g_err; /* failure state from exc handler */

typedef struct {
    vm_address_t    page_addr;
    vm_size_t       pagesize;
    vm_offset_t     data; /* The entire page */
    vm_prot_t       protection;
} page_restore_t;

#if defined(__arm64__)
typedef arm_thread_state64_t att_threadstate_t;
#elif defined(__x86_64__)
typedef x86_thread_state64_t att_threadstate_t;
#endif

struct allocation {
    vm_address_t addr;
    vm_size_t size;
};

/**
 * Private data for the exception handler to maintain state between
 * exceptions.
 */
static __thread struct state_slot {
    thread_act_t thread;
    struct allocation allocation; /* page allocated to inject code into */
    att_threadstate_t orig_threadstate;
} t_threadstate[16];


struct pyfn_addrs {
    vm_address_t breakpoint_addr;
    vm_address_t PyRun_SimpleString;
};

#define PYTHON_CODE_OFFSET  16

/*
 * Data passed to the exception handler thread.
 * All borrowed.
 */
struct handler_args {
    enum {
        HANDLE_SOFTWARE = 0,
        HANDLE_HARDWARE = 1 ,
    } exc_type;
    char* python_code;        /* code to execute */
    struct pyfn_addrs pyfn_addrs;
    page_restore_t breakpoint_restore;
    int count_threads;
    mach_port_t exc_port;
    semaphore_t started;    /* signaled when the handler thread starts */
    semaphore_t completed;  /* signaled once after each injection */ // TODO
    struct {
        thread_act_t act;
        _Atomic int refcount; /**/
    }* last_completed;
};

/*
 * The handler thread keeps it's own threadlocal copy of it's args
 * in order to pass across the mach_msg_server boundary
 */
static __thread struct handler_args t_handler_args;

/*
 * Each field is an array to simplify the usage.
 */
struct old_exc_port {
    exception_mask_t        masks[1];
    exception_handler_t     ports[1];
    exception_behavior_t    behaviors[1];
    thread_state_flavor_t   flavors[1];
};

struct tgt_thread {
    uint64_t            thread_id;
    thread_act_t        act;
    mach_port_t         exception_port;
    uint32_t            running     : 1,
                        hw_bp_set   : 1,
                        /*
                         * What we actually mean is that we're still hoping
                         * the code will execute. We'll set this to 0 also
                         * when the thread dies.
                         */
                        attached    : 1;
    struct old_exc_port old_exc_port;
};


static vm_address_t find_pyfn(task_t task, const char* symbol);
static vm_address_t find_sysfn(task_t task, void* addr, const char* symbol);

/*
 * x16 must be set to the address of _write
 */
void injection();
void end_of_injection();
#if defined(__arm64__)
__asm__ ("\
	.global _injection\n\
	.p2align	2\n\
_injection:\n\
	blr	x16\n\
	brk	#0xf000\n\
	.global _inj_callback\n\
_end_of_injection:\n\
	b	_injection\n\
");
#elif defined(__x86_64__)
__asm__ ("\
	.global _injection\n\
	.p2align	2\n\
_injection:\n\
	callq	*%rax\n\
	int3\n\
	.global _inj_callback\n\
_end_of_injection:\n\
	jmp	_injection\n\
");
#endif // __arm64__

__attribute__((format(printf, 1, 2)))
static int
log_dbg(const char* fmt, ...)
{
    va_list valist;
    va_start(valist, fmt);

    if (debug) {
        fprintf(stderr, "[debug]: ");
        vfprintf(stderr, fmt, valist);
        if (fmt[strlen(fmt) - 1] != '\n') {
            fprintf(stderr, "\n");
        }
    }

    va_end(valist);
    return 0;  // we only return int to satisfy __builtin_dump_struct on
               // ventura
}

__attribute__((format(printf, 1, 2)))
static void
log_err(const char* fmt, ...)
{
    va_list valist;
    va_start(valist, fmt);
    int esaved = errno;

    fprintf(stderr, "attacher: ");
    vfprintf(stderr, fmt, valist);

    if (fmt[strlen(fmt) - 1] != '\n') {
        fprintf(stderr, ": %s\n", strerror(esaved));
    }

    va_end(valist);
}

static void
log_mach(const char* msg, kern_return_t kr)
{
    fprintf(stderr, "attacher: %s: %s (%d)\n", msg, mach_error_string(kr), kr);
}

static int
load_and_find_safepoint(const char* sopath, const char* symbol, Dl_info* info)
{
    void* handle = dlopen(sopath, RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL) {
        log_err("dlopen: %s\n", dlerror());
        return 1;
    }

    void* faddr = dlsym(handle, symbol);
    if (faddr == NULL) {
        return 1;
    }

    if (dladdr(faddr, info) == 0) { // yes, 0 means failure for dladdr
        log_err("dladdr: %s\n", dlerror());
        info = NULL;
        return 1;
    }
    assert(strcmp(info->dli_sname, symbol) == 0);
    if (strcmp(info->dli_fname, sopath) != 0) {
        log_err("info->dli_fname = %s\n", info->dli_fname);
        log_err("         sopath = %s\n", sopath);
        return 1;
    }
    return 0;
}

static void
fmt_prot(char out[4], vm_prot_t protection)
{
    out[0] = (protection & VM_PROT_READ) ? 'r' : '-';
    out[1] = (protection & VM_PROT_WRITE) ? 'w' : '-';
    out[2] = (protection & VM_PROT_EXECUTE) ? 'x' : '-';
    out[3] = '\0';
}

static kern_return_t
restore_page(task_t task, page_restore_t* r)
{
    kern_return_t kr = 0;
    if ((kr = vm_protect(task,  r->page_addr, r->pagesize, false,
                    VM_PROT_READ|VM_PROT_WRITE)) != KERN_SUCCESS) {
        return kr;
    }
    if ((kr = vm_write(task, r->page_addr, r->data, r->pagesize))
            != KERN_SUCCESS) {
        log_mach("vm_write", kr);
    }
    /* restore the protection to avoid bus errors */
    kern_return_t kr2;
    if ((kr2 = vm_protect(task, r->page_addr, r->pagesize, false,
                    r->protection)) != KERN_SUCCESS) {
        return kr2;
    }
    return kr;
}

static kern_return_t
suspend_and_restore_page(task_t task, page_restore_t* r)
{
    int kr, kr2;
    if ((kr = task_suspend(task)) != 0) {
        log_mach("task_suspend", kr);
    }
    if ((kr2 = restore_page(task, r)) != 0) {
        log_mach("restore_page", kr2);
        return kr2;
    }
    return kr;
}

static kern_return_t
get_region_protection(task_t task, vm_address_t page_addr, int* protection)
{
    kern_return_t kr;
    vm_address_t region_address = page_addr;
    vm_size_t region_size = 0;
    struct vm_region_basic_info_64 region_info = {};
    mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    if ((kr = vm_region_64(task, &region_address, &region_size,
                    VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region_info,
                    &infoCnt, &object_name)
                ) != KERN_SUCCESS) {
        log_mach("vm_region_64", kr);
        return kr;
    }

    *protection = region_info.protection;
    return kr;
}

#if defined(__arm64__)
static int
set_hw_breakpoint(struct tgt_thread* thrd, uintptr_t bp_addr)
{
    kern_return_t kr;

    __auto_type thread = thrd->act;
    arm_debug_state64_t debug_state = {};
    __auto_type stateCnt = ARM_DEBUG_STATE64_COUNT;
    if ((kr = thread_get_state(thread, ARM_DEBUG_STATE64,
                    (thread_state_t)&debug_state, &stateCnt)) != 0) {
        log_mach("thread_get_state", kr);
        return ATT_FAIL;
    }

    if (debug_state.__bvr[0] != 0) {
        log_err("debug registers in use");
        // I mean... who else is using them?
        return ATT_FAIL;
    }

    uint32_t ctrl = 0;
    ctrl |= (0xf << 5); /* BAS: match A64 / A32 instruction */
    ctrl |= (0b10 << 1); /* PMC: Select EL0 only */
    ctrl |= 1; /* Enable breakpoint */

    debug_state.__bcr[0] = ctrl;
    debug_state.__bvr[0] = bp_addr;

    log_dbg("state:\n");
    for (int i = 0; i < 1; i++) {
        log_dbg("bvr[%02d] = 0x%llx\n", i, debug_state.__bvr[i]);
        log_dbg("bcr[%02d] = 0x%llx\n", i, debug_state.__bcr[i]);
    }

    if ((kr = thread_set_state(thread, ARM_DEBUG_STATE64,
                       (thread_state_t)&debug_state, stateCnt)) != 0) {
        log_mach("thread_set_state", kr);
        return ATT_FAIL;
    }
    thrd->hw_bp_set = 1;
    return 0;
}

static int
remove_hw_breakpoint(struct tgt_thread* thrd)
{
    kern_return_t kr;

    __auto_type thread = thrd->act;
    arm_debug_state64_t debug_state = {};
    __auto_type stateCnt = ARM_DEBUG_STATE64_COUNT;
    if ((kr = thread_get_state(thread, ARM_DEBUG_STATE64,
                    (thread_state_t)&debug_state, &stateCnt)) != 0) {
        log_mach("thread_get_state", kr);
        return ATT_FAIL;
    }

    if (debug_state.__bvr[0] == 0 && debug_state.__bcr[0] == 0) {
        log_err("hw bp not set :/");
        thrd->hw_bp_set = 0;
        return 0;
    }

    debug_state.__bcr[0] = 0ULL;
    debug_state.__bvr[0] = 0ULL;

    if ((kr = thread_set_state(thread, ARM_DEBUG_STATE64,
                       (thread_state_t)&debug_state, stateCnt)) != 0) {
        log_mach("thread_set_state", kr);
        return ATT_FAIL;
    }
    thrd->hw_bp_set = 0;
    return 0;
}
#endif /* __arm64__ */

// backport for macOS < 14
#ifndef TASK_MAX_EXCEPTION_PORT_COUNT
#define TASK_MAX_EXCEPTION_PORT_COUNT EXC_TYPES_COUNT
#endif // TASK_MAX_EXCEPTION_PORT_COUNT

// Adapted from https://gist.github.com/rodionovd/01fff61927a665d78ecf
static struct {
    mach_msg_type_number_t count;
    exception_mask_t      masks[TASK_MAX_EXCEPTION_PORT_COUNT];
    exception_handler_t   ports[TASK_MAX_EXCEPTION_PORT_COUNT];
    exception_behavior_t  behaviors[TASK_MAX_EXCEPTION_PORT_COUNT];
    thread_state_flavor_t flavors[TASK_MAX_EXCEPTION_PORT_COUNT];
} old_exc_ports; // FIXME: don't use static

static int
prepare_exc_port(mach_port_t* exc_port)
{
    kern_return_t kr = 0;
    mach_port_t me = mach_task_self();
    if ((kr = mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE, exc_port))
            != KERN_SUCCESS) {
        log_mach("mach_port_allocate", kr);
        return ATT_FAIL;
    }
    if ((kr = mach_port_insert_right(me, *exc_port, *exc_port,
                    MACH_MSG_TYPE_MAKE_SEND)) != KERN_SUCCESS) {
        log_mach("mach_port_insert_right", kr);
        return ATT_FAIL;
    }
    return 0;
}

static int
setup_exception_handling(task_t target_task, mach_port_t* exc_port)
{
    kern_return_t kr = 0;
    int err;

    if ((err = prepare_exc_port(exc_port)) != 0) {
        return err;
    }

    old_exc_ports.count = TASK_MAX_EXCEPTION_PORT_COUNT;

    exception_mask_t mask = EXC_MASK_BREAKPOINT;

    /* get the old exception ports */
    if ((kr = task_get_exception_ports(
                    target_task, mask, old_exc_ports.masks,
                    &old_exc_ports.count, old_exc_ports.ports,
                    old_exc_ports.behaviors, old_exc_ports.flavors))
            != KERN_SUCCESS) {
        log_mach("task_get_exception_ports", kr);
        return ATT_FAIL;
    }

    task_flavor_t flavor =
#if defined(__arm64__)
        ARM_THREAD_STATE64
#elif defined(__x86_64__)
        x86_THREAD_STATE64
#endif
        ;

    /* set the new exception ports */
    if ((kr = task_set_exception_ports(target_task, mask, *exc_port,
                    EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                    flavor)) != KERN_SUCCESS) {
        log_mach("task_set_exception_ports", kr);
        return ATT_FAIL;
    }
    return ATT_SUCCESS;
}

__attribute__((unused))
static int
setup_thread_exc_handling(thread_act_t thread, mach_port_t* exc_port,
        struct old_exc_port* old)
{
    kern_return_t kr = 0;

    exception_mask_t mask = EXC_BREAKPOINT;
    mach_msg_type_number_t count = 1; /* only 1 mask to be replaced  */

    task_flavor_t flavor =
#if defined(__arm64__)
        ARM_THREAD_STATE64
#elif defined(__x86_64__)
        x86_THREAD_STATE64
#endif
        ;

    if ((kr = thread_swap_exception_ports(thread, mask, *exc_port,
                    EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                    flavor, old->masks, &count, old->ports, old->behaviors,
                    old->flavors)) != 0) {
        log_mach("thread_swap_exception_ports", kr);
        return ATT_FAIL;
    }
    return ATT_SUCCESS;
}

__attribute__((unused))
static int
restore_thread_exc_handlers(thread_act_t thread, struct old_exc_port* old)
{
    kern_return_t kr = 0;

    if (old->masks[0]) {
        kr = thread_set_exception_ports(thread, old->masks[0], old->ports[0],
                old->behaviors[0], old->flavors[0]);
        if (kr != KERN_SUCCESS) {
            log_mach("thread_set_exception_ports", kr);
            return ATT_FAIL;
        }
    }
    return 0;
}

static struct state_slot*
find_state_slot(mach_port_t thread)
{
    int n = NELEMS(t_threadstate);
    for (int i = 0; i < n; i++) {
        if (t_threadstate[i].thread == thread) {
            return &t_threadstate[i];
        }
    }
    for (int i = 0; i < n; i++) {
        if (t_threadstate[i].thread == 0) {
            t_threadstate[i].thread = thread;
            return &t_threadstate[i];
        }
    }
    return NULL;
}

extern kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
        mach_port_t thread,
        mach_port_t task,
        exception_type_t exception,
        mach_exception_data_t code,
        mach_msg_type_number_t code_count)
{
    log_err("unexected call: catch_mach_exception_raise\n");
    return KERN_NOT_SUPPORTED;
}


extern kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
        exception_type_t exception,
        const mach_exception_data_t code,
        mach_msg_type_number_t code_count,
        int * flavor,
        const thread_state_t old_state,
        mach_msg_type_number_t old_state_count,
        thread_state_t new_state,
        mach_msg_type_number_t * new_state_count)
{
    log_err("unexected call: catch_mach_exception_raise_state\n");
    return KERN_NOT_SUPPORTED;
}

extern kern_return_t
catch_mach_exception_raise_state_identity(
        mach_port_t exception_port,
        mach_port_t thread,
        mach_port_t task,
        exception_type_t exception,
        mach_exception_data_t code,
        mach_msg_type_number_t codeCnt,
        int *flavor,
        thread_state_t old_state,
        mach_msg_type_number_t old_stateCnt,
        thread_state_t new_state,
        mach_msg_type_number_t *new_stateCnt)
{
    kern_return_t kr;

    log_dbg("in catch_exception_raise_state_identity for %d", thread);
    log_dbg("codeCnt = %d", codeCnt);
    if (codeCnt > 0) {
        log_dbg("code = %llx\n", *code);
    }
    assert(exception == EXC_BREAKPOINT);
    #if defined(__arm64__)
        assert(*flavor == ARM_THREAD_STATE64);
        assert(old_stateCnt == ARM_THREAD_STATE64_COUNT);
    #elif defined(__x86_64__)
        assert(*flavor == x86_THREAD_STATE64);
        assert(old_stateCnt == x86_THREAD_STATE64_COUNT);
    #endif

    if (debug) {
        __builtin_dump_struct((att_threadstate_t*)old_state, &log_dbg);
    }

    // Copy old state to new state!
    memcpy(new_state, old_state, old_stateCnt * sizeof(natural_t));
    *new_stateCnt = old_stateCnt;

    att_threadstate_t* state = (att_threadstate_t*)new_state;


    // Find state slot for thread.

    __auto_type state_slot = find_state_slot(thread);
    if (state_slot == NULL) {
        fprintf(stderr, "out of state slots!!!");
        abort();
    }

    struct handler_args* handler = &t_handler_args;

    uint64_t pc =
        #if defined(__arm64__)
            arm_thread_state64_get_pc(*state);
        #elif defined(__x86_64__)
            state->__rip;
        #endif
    __auto_type bp_addr = handler->pyfn_addrs.breakpoint_addr;
    if (pc >= bp_addr && pc < bp_addr + 2) { // it's a range because of x86
        if (handler->exc_type == HANDLE_SOFTWARE) {
            if (handler->breakpoint_restore.page_addr == 0) {
                abort();
            }
            /*
             * Restore overwritten instruction
             */
            kr = restore_page(task, &handler->breakpoint_restore);
            if (kr != KERN_SUCCESS) {
                log_mach("restore_page", kr);
                atomic_store(&g_err , ATT_UNKNOWN_STATE);
                handler->last_completed->act = thread;
                semaphore_signal(handler->completed); // XXX: err handling
                return KERN_FAILURE; /* I think it'll die anyway */
            }
        } else {
            #if defined(__arm64__)
                assert(handler->exc_type == HANDLE_HARDWARE);

                struct tgt_thread thrd = { .act = thread, };
                int err = remove_hw_breakpoint(&thrd);
                if (err != 0) {
                    atomic_store(&g_err, ATT_UNKNOWN_STATE);
                    handler->last_completed->act = thread;
                    semaphore_signal(handler->completed); // XXX: err handling
                    return KERN_FAILURE;
                }
            #elif defined(__x86_64__)
                // TODO
                log_err("x86_64: exc_handler_type != HANDLE_SOFTWARE");
                abort();
            #endif /* __arm64__ */
        }

        // This is our last chance to bail.
        int expected = 0;
        if (!atomic_compare_exchange_strong(&g_err, &expected,
                    ATT_UNKNOWN_STATE)) {
            // Either the timeout or a signal beat us but wasn't finished
            // restoring the page. They can still continue though.
            return KERN_SUCCESS;
        }

        /* copy in code and data for hijack */

        vm_size_t pagesize = getpagesize();
        vm_address_t allocated = 0;
        kr = vm_allocate(task, &allocated, pagesize, true);
        if (kr != KERN_SUCCESS) {
            log_mach("vm_allocate", kr);
            g_err = ATT_FAIL; // technically we're leaking memory...
            handler->last_completed->act = thread;
            semaphore_signal(handler->completed); // XXX: err handling
            return KERN_SUCCESS;
        }
        /* save so we can deallocate at the end */
        state_slot->allocation.addr = allocated;
        state_slot->allocation.size = pagesize;

        // ... we could use malloc but this is the right size.
        vm_offset_t data;
        mach_msg_type_number_t dataCnt;
        if ((kr = vm_read(task, allocated, pagesize, &data, &dataCnt))
                != KERN_SUCCESS) {
            log_mach("vm_read", kr);
            g_err = ATT_FAIL;
            handler->last_completed->act = thread;
            semaphore_signal(handler->completed); // XXX: err handling
            return KERN_SUCCESS;
        }
        assert(dataCnt == pagesize);

        size_t inj_len = end_of_injection - injection;
        assert(inj_len <= PYTHON_CODE_OFFSET);
        memcpy((void*)data, injection, inj_len);

        const char* arg = handler->python_code;
        size_t len = strlen(arg) + 1;
        assert(PYTHON_CODE_OFFSET + len <= pagesize);
        memcpy((char*)data + PYTHON_CODE_OFFSET, arg, len);

        page_restore_t page_restore = {
            .page_addr = allocated,
            .pagesize = pagesize,
            .data = data,
            .protection = VM_PROT_READ | VM_PROT_EXECUTE,
        };
        if ((kr = restore_page(task, &page_restore)) != KERN_SUCCESS) {
            log_mach("restore_page", kr);
            g_err = ATT_FAIL;
            handler->last_completed->act = thread;
            semaphore_signal(handler->completed);
            return KERN_SUCCESS;
        }

        /*
         * set up call
         */

        vm_address_t fn_addr = handler->pyfn_addrs.PyRun_SimpleString;
        assert(fn_addr);

        state_slot->orig_threadstate = *state;

        #if defined(__arm64__)
            state->__x[0] = allocated + 16;
            state->__x[16] = fn_addr;
            arm_thread_state64_set_pc_fptr(*state, allocated);
        #elif defined(__x86_64__)
            state->__rdi = allocated + 16;
            state->__rax = fn_addr;
            state->__rip = allocated;
            state->__rsp &= -16LL; // 16-byte align stack
        #endif

    } else {
        /*
         * We've come back from PyRun_SimpleString
         */
        log_dbg("in the second breakpoint");
        if (
            #if defined(__arm64__)
                arm_thread_state64_get_pc(state_slot->orig_threadstate) == 0
            #elif defined(__x86_64__)
                state_slot->orig_threadstate.__rip == 0
            #endif
        ) {
            log_err("thread state empty");
            abort();
        }
        assert(state_slot->allocation.addr != 0 &&
                state_slot->allocation.size != 0);

        uint64_t retval =
            #if defined(__arm64__)
                state->__x[0];
            #elif defined(__x86_64__)
                state->__rax;
            #endif

        *(att_threadstate_t*)new_state = state_slot->orig_threadstate;
        #ifdef __x86_64__
            if (HANDLE_SOFTWARE) {
                // 0xcc on x86 progresses the instruction pointer to the
                // instruction after the trap instruction. But since we
                // replaced it, we need to go back and execute it.
                ((att_threadstate_t*)new_state)->__rip -= 1;
            }
        #endif

        kr = vm_deallocate(task, state_slot->allocation.addr,
                state_slot->allocation.size);
        if (kr != KERN_SUCCESS) {
            log_mach("vm_deallocate", kr);
        }
        state_slot->allocation.addr = state_slot->allocation.size = 0;
        state_slot->thread = 0;

        if (retval != 0) {
            log_err("PyRun_SimpleString failed (%d)", (int)retval);
        }
        g_err = (retval == 0) ? ATT_SUCCESS : ATT_FAIL;
        handler->last_completed->act = thread;
        semaphore_signal(handler->completed);
    }

    return KERN_SUCCESS;
}

/*
 * This is implemented by the mig generated code in mach_excServer.c
 */
extern boolean_t mach_exc_server(mach_msg_header_t *, mach_msg_header_t *);

static void *
exception_server_thread(void* arg)
{
    kern_return_t kr;

    /* copy the args into our thread local space */
    t_handler_args = *(struct handler_args *)arg;
    struct handler_args* args = &t_handler_args;

    /* duplicate the python code in case we outlive our parent thread */
    args->python_code = strdup(args->python_code);
    if (!args->python_code) {
        log_err("strdup");
        return NULL;
    }

    atomic_fetch_add(&args->last_completed->refcount, 1);


    semaphore_signal(args->started);

    // It would perhaps be better to have the main thread signal when all is
    // done?
    const int breakpoints_per_thread = 2;
    for (int i = 0; i < args->count_threads * breakpoints_per_thread; i++) {
        if ((kr = mach_msg_server_once(mach_exc_server,
                        MACH_MSG_SIZE_RELIABLE, args->exc_port, 0))
                != KERN_SUCCESS) {
            log_mach("mach_msg_server_once", kr);
            break;
        }
    }

    if (1 == atomic_fetch_sub(&args->last_completed->refcount, 1)) {
        free(args->last_completed);
        args->last_completed = NULL;
    }
    free(args->python_code);
    args->python_code = NULL;
    return NULL;
}

static sigset_t
init_signal_mask()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGUSR1);
    return mask;
}

static void *
signal_handler_thread(void *arg)
{
    sigset_t mask = init_signal_mask();
    semaphore_t sync_sema = *(semaphore_t*)arg;

    for (;;) {
        int signo;
        errno = sigwait(&mask, &signo);
        if (errno != 0) {
            log_err("BUG: sigwait");
            abort();  // only known error is EINVAL - so it's a bug.
        }
        if (signo == SIGUSR1) {
            // Used internally to shut down this thread.
            return NULL;
        } else {
            int expected = 0;
            if (atomic_compare_exchange_strong(&g_err, &expected,
                        ATT_INTERRUPTED)) {
                semaphore_signal(sync_sema);
            } else {
                fprintf(stderr,
                        "Hold on a mo, we're in the middle of surgery. "
                        "Will be done in a few seconds.\n");
                // Are we supposed to redeliver the signal to ourselves
                // in order to be cancelled after we unblock?
                if (raise(signo) == -1) { // doesn't seem to work.
                    log_err("failed to re-raise signal");
                }
                return NULL;
            }
        }
    }
}
static int
shutdown_signal_thread(pthread_t thread)
{
    // Set errno, because our log_err function likes it
    errno = pthread_kill(thread, SIGUSR1);
    return errno;
}

struct dyld_image_info_it {
    struct dyld_all_image_infos infos;
    struct dyld_image_info info;
    char filepath[1024];
    unsigned int idx;
};

static void
iter_dyld_infos(task_t task, struct dyld_image_info_it* it)
{
    kern_return_t kr = 0;

    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if ((kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count))
            != KERN_SUCCESS) {
        log_mach("task_info", kr);
        return;
    }

    assert(it->infos.infoArrayCount == 0);

    vm_size_t outsize = 0;
    if ((kr = vm_read_overwrite(task, dyld_info.all_image_info_addr,
                    sizeof it->infos, (vm_address_t)&it->infos, &outsize))
            != KERN_SUCCESS) {
        log_mach("vm_read_overwrite", kr);
        memset(it, 0, sizeof *it);
        return;
    }
    assert(it->infos.infoArrayCount <= 1000);

    if (it->infos.infoArray == NULL) {
        // TODO: sleep-wait
        log_err("dyld_all_image_infos is being modified.\n");
        memset(it, 0, sizeof *it);
    }
}

static bool
iter_dyld_infos_next(task_t task, struct dyld_image_info_it* it)
{
    kern_return_t kr;
    unsigned int i = it->idx;
    if (!(i < it->infos.infoArrayCount)) {
        return false;
    }

    vm_size_t outsize = 0;

    kr = vm_read_overwrite(task, (vm_address_t)&it->infos.infoArray[i],
            sizeof it->info, (vm_address_t)&it->info, &outsize);
    if (kr != KERN_SUCCESS) {
        log_mach("vm_read_overwrite", kr);
        return false;
    }
    assert(outsize >= sizeof it->info);

    kr = vm_read_overwrite(task, (vm_address_t)it->info.imageFilePath,
                    sizeof it->filepath, (vm_address_t)it->filepath, &outsize);
    if (kr != KERN_SUCCESS) {
        log_mach("vm_read_overwrite", kr);
        return false;
    }
    // check for overruns... no idea if that can happen.
    assert(outsize <= 1024);
    // ensure null termination
    it->filepath[1023] = '\0';

    it->info.imageFilePath = it->filepath;

    it->idx++;
    return true;
}


/*
 * NB: Makes the assumption that python loads the same system
 * libraries. i.e. they are they same version. If not, the symbol is
 * not found.
 */
__attribute__((unused)) // silence warning
static vm_address_t
find_sysfn(task_t task, void* fptr, const char* symbol)
{
    Dl_info dlinfo = {};
    if (dladdr(fptr, &dlinfo) == 0) { // yes, 0 means failure for dladdr
        log_err("attacher: dladdr: %s\n", dlerror());
        return 0;
    }
    assert(strcmp(dlinfo.dli_sname, symbol) == 0);

    vm_address_t fn_addr = 0;

    struct dyld_image_info_it it = {};
    iter_dyld_infos(task, &it);
    for (; iter_dyld_infos_next(task, &it); ) {
        if (strcmp(it.info.imageFilePath, dlinfo.dli_fname) == 0) {
            ptrdiff_t offset = dlinfo.dli_saddr - dlinfo.dli_fbase;

            fn_addr = (vm_address_t)it.info.imageLoadAddress + offset;
            break;
        }
    }
    return fn_addr;
}


static vm_address_t
find_pyfn(task_t task, const char* symbol)
{
    vm_address_t fn_addr = 0;
    struct dyld_image_info_it it = {};
    iter_dyld_infos(task, &it);
    for (; iter_dyld_infos_next(task, &it); ) {
        // basename may modify its argument on certain platforms. so we
        // make a copy. ... even though this code is only for macOS
        char bn[1024];
        memcpy(bn, it.filepath, 1024);
        if (strcmp(basename(bn), PYTHON_SO_BASENAME) == 0) {
            log_dbg("looking in %s", it.filepath);

            Dl_info dlinfo = {};
            if (load_and_find_safepoint(it.filepath, symbol, &dlinfo) != 0) {
                continue;
            }
            log_dbg("found %s in %s", symbol, it.filepath);
            ptrdiff_t breakpoint_offset = dlinfo.dli_saddr - dlinfo.dli_fbase;

            fn_addr =
                (vm_address_t)it.info.imageLoadAddress + breakpoint_offset;
            if (!debug) {
                break;
            }
        }

    }
    errno = 0; // that search process above leaves the errno dirty
    return fn_addr;
}


static int
find_needed_python_funcs(task_t task, struct pyfn_addrs* addrs)
{
    addrs->breakpoint_addr = find_pyfn(task, SAFE_POINT);
    if (!addrs->breakpoint_addr) {
        log_err("could not find %s in shared libs\n", SAFE_POINT);
        return ATT_FAIL;
    }
    addrs->PyRun_SimpleString = find_pyfn(task, "PyRun_SimpleString");
    if (!addrs->PyRun_SimpleString) {
        log_err("could not find %s in shared libs\n", "PyRun_SimpleString");
        return ATT_FAIL;
    }
    return 0;
}


static int
wait_for_probe_installation(semaphore_t sync_sema, int timeout_s)
{
    kern_return_t kr;

    mach_timespec_t initial_timeout = { .tv_sec = timeout_s, };
    mach_timespec_t timeout2 = { .tv_sec = 10, };

    kr = semaphore_timedwait(sync_sema, initial_timeout);
    if (kr != KERN_SUCCESS) {
        if (kr != KERN_OPERATION_TIMED_OUT && kr != KERN_ABORTED) {
            log_mach("semaphore_timedwait", kr);
        }
        int expected = 0;
        if (!atomic_compare_exchange_strong(&g_err, &expected,
                    ATT_INTERRUPTED)) {
            fprintf(stderr, "Waiting 10s more as it seems we're making "
                    "progress\n");
            if (0 == semaphore_timedwait(sync_sema, timeout2)) {
                return 0;
            }
        }
        return kr;
    }
    return 0;
}


static int
get_task(int pid, task_t* task)
{
    kern_return_t kr;
    *task = TASK_NULL;
    if ((kr = task_for_pid(mach_task_self(), pid, task)) != KERN_SUCCESS) {
        log_mach("task_for_pid", kr);
        if (kr == KERN_FAILURE) {
            if (geteuid() != 0) {
                log_err("try as root (e.g. using sudo)\n");
            } else {
                log_err("if the target Python is the system Python, try using "
                        "a Homebrew or Macports build instead\n");
            }
        }
        return ATT_FAIL;
    }
    return 0;
}


int
init_handler_args(struct handler_args* args)
{
    kern_return_t kr;
    task_t me = mach_task_self();
    kr = semaphore_create(me, &args->started, SYNC_POLICY_FIFO, 0);
    if (kr != KERN_SUCCESS) {
        log_mach("semaphore_create", kr);
        return ATT_FAIL;
    }
    kr = semaphore_create(me, &args->completed, SYNC_POLICY_FIFO, 0);
    if (kr != KERN_SUCCESS) {
        log_mach("semaphore_create", kr);
        return ATT_FAIL;
    }

    args->last_completed = calloc(1, sizeof *args->last_completed);
    if (args->last_completed == NULL) {
        log_err("calloc");
        return ATT_FAIL;
    }
    atomic_fetch_add(&args->last_completed->refcount, 1);
    return 0;
}

void
deinit_handler_args(struct handler_args* args)
{
    kern_return_t kr;
    if (1 == atomic_fetch_sub(&args->last_completed->refcount, 1)) {
        free(args->last_completed);
        args->last_completed = NULL;
    }
    task_t me = mach_task_self();
    if (args->completed) {
        if ((kr = semaphore_destroy(me, args->completed)) != KERN_SUCCESS) {
            log_mach("semaphore_destroy", kr);
        }
        args->completed = 0;
    }
    if (args->started) {
        if ((kr = semaphore_destroy(me, args->started)) != KERN_SUCCESS) {
            log_mach("semaphore_destroy", kr);
        }
        args->started = 0;
    }
}


int
attach_and_execute(const int pid, const char* python_code)
{
    int err = 0;
    kern_return_t kr;
    struct handler_args args = {};

    // TODO: This code is hilariously non-reentrant. Find a way to
    // protect it. or make it reentrant.

    g_err = 0; // Have to restore this to 0

    task_t task;
    if ((err = get_task(pid, &task)) != 0) {
        return err;
    }

    vm_size_t pagesize = getpagesize();

    if (PYTHON_CODE_OFFSET + strlen(python_code) + 1 > pagesize) {
        log_err("python code exceeds max size: %lu\n",
                pagesize - PYTHON_CODE_OFFSET - 1);
        return ATT_FAIL;
    }

    // Find some python fn addresses in advance of playing around with
    // setting breakpoints.
    struct pyfn_addrs pyfn_addrs = {};
    if (find_needed_python_funcs(task, &pyfn_addrs) != 0) {
        return ATT_FAIL;
    }

    vm_address_t breakpoint_addr = pyfn_addrs.breakpoint_addr;
    log_dbg(SAFE_POINT " is at %p in process %d\n",
            (void*)breakpoint_addr, pid);


    // work out page to read and write

    vm_address_t page_boundary = breakpoint_addr & ~(pagesize - 1);
    vm_offset_t bp_page_offset = breakpoint_addr & (pagesize - 1);

    // Attach and set breakpoint
    if ((kr = task_suspend(task)) != KERN_SUCCESS) {
        log_mach("task_suspend", kr);
        return ATT_FAIL;
    }

    vm_offset_t data;
    mach_msg_type_number_t dataCnt;
    if ((kr = vm_read(task, page_boundary, pagesize, &data, &dataCnt))
            != KERN_SUCCESS) {
        log_mach("vm_read", kr);
        return ATT_FAIL;
    }
    assert(dataCnt == pagesize);
    void* local_bp_addr = (char*)data + (ptrdiff_t)bp_page_offset;

    uint32_t saved_instruction = *(uint32_t*)local_bp_addr;
    log_dbg("instr at BP: %8x\n", saved_instruction);

    /* write the breakpoint */
#if defined(__arm64__)
    *(uint32_t*)local_bp_addr = DEBUG_TRAP_INSTR;
#else /* __x86_64__ */
    *(uint8_t*)local_bp_addr = DEBUG_TRAP_INSTR;
#endif


    int protection;
    kr = get_region_protection(task, page_boundary, &protection);
    if (kr != KERN_SUCCESS) {
        log_mach("get_region_protection", kr);
        return ATT_FAIL;
    }

    if (debug) {
        char prot_str[4];
        fmt_prot(prot_str, protection);
        log_dbg("region.protection = %s", prot_str);
    }

    if (init_handler_args(&args) != 0) {
        deinit_handler_args(&args);
        return ATT_FAIL;
    }

    /*
     * Now we enter the critical section, so we block signals until
     * we've set things up and are in a good state to reverse them
     * on a ctrl-c
     */

    sigset_t old_mask = 0;
    sigset_t signal_mask = init_signal_mask();
    if ((errno = pthread_sigmask(SIG_BLOCK, &signal_mask, &old_mask)) != 0) {
        log_err("pthread_sigmask");
        return ATT_FAIL;
    }
    pthread_t t_sig_handler;
    if ((errno = pthread_create(&t_sig_handler, NULL, signal_handler_thread,
                    &args.completed)) != 0) {
        log_err("pthread_create");
        err = ATT_FAIL;
        goto restore_mask;
    }

    page_restore_t page_restore = {
        .page_addr = page_boundary,
        .pagesize = pagesize,
        .data = data,
        .protection = protection,
    };
    if ((kr = restore_page(task, &page_restore)) != KERN_SUCCESS) {
        log_mach("restore_page", kr);
        err = ATT_UNKNOWN_STATE;
        goto restore_mask;
    }

    /*
     * We restore the instruction on our copy of the page so that we
     * are prepared to unset the breakpoint in the exception handler
     */
    *(uint32_t*)local_bp_addr = saved_instruction;

    mach_port_t exception_port = MACH_PORT_NULL;

    if (setup_exception_handling(task, &exception_port) != 0) {
        err = ATT_FAIL;
        if (restore_page(task, &page_restore) != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        goto restore_mask;
    }

    args.exc_type = HANDLE_SOFTWARE;
    args.python_code = (char*)python_code;
    args.pyfn_addrs = pyfn_addrs;
    args.breakpoint_restore = page_restore;
    args.count_threads = 1;
    args.exc_port = exception_port;

    pthread_t s_exc_thread;
    if (pthread_create(&s_exc_thread, NULL, exception_server_thread,
            &args) != 0) {
        log_err("pthread_create");
        err = ATT_FAIL;
        if (restore_page(task, &page_restore) != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        goto out;
    }

    if ((kr = semaphore_wait(args.started)) != KERN_SUCCESS) {
        log_mach("waiting for pthread_create", kr);
        err = ATT_FAIL;
        if (restore_page(task, &page_restore) != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        goto out;
    }

    fprintf(stderr, "Waiting for process to reach safepoint...\n");
    if ((kr = task_resume(task)) != KERN_SUCCESS) {
        log_mach("task_resume", kr);
        err = ATT_FAIL;
        if (restore_page(task, &page_restore) != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        goto out;
    }

    if ((kr = wait_for_probe_installation(args.completed, 30)) != 0) {
        int kr2 = suspend_and_restore_page(task, &page_restore);
        if (kr == KERN_OPERATION_TIMED_OUT) {
            log_err("timed out after 30s waiting to reach safe point");
        }
        err = atomic_load(&g_err);
        if (err == 0) { abort(); }; // bug in concurrency code.
        if (kr2 != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        // It seems like here, we are forgetting to resume the task...

        // Assuming no race with the exception handler, (which we will ensure
        // in the future), we're back to original state.
        goto out;
    }

    // check error code set in the exception handler.
    err = g_err;

    if (err == ATT_INTERRUPTED) {
        kr = suspend_and_restore_page(task, &page_restore);
        if (kr != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        } else {
            fprintf(stderr, "Cancelled\n");
        }
    }

out:
    // uninstall exception handlers
    for (int i = 0; i < (int)old_exc_ports.count; i++) {
        kr = task_set_exception_ports(task,
                old_exc_ports.masks[i],
                old_exc_ports.ports[i],
                old_exc_ports.behaviors[i],
                old_exc_ports.flavors[i]);
        if (kr != KERN_SUCCESS) {
            log_mach("task_set_exception_ports", kr);
            err = ATT_UNKNOWN_STATE;
        }
    }

    if (shutdown_signal_thread(t_sig_handler) != 0) {
        log_err("shutdown_signal_thread");
    }

restore_mask:
    if ((errno = pthread_sigmask(SIG_SETMASK, &old_mask, NULL))) {
        log_err("BUG: pthread_sigmask");
        abort();  // can only be EINVAL
    }
    deinit_handler_args(&args);

    return err;
}

#ifdef __x86_64__
__attribute__((unused))
#endif // __x86_64__
static int
find_tid(uint64_t tid, uint64_t* tids, int count_tids)
{
    for (int i = 0; i < count_tids; i++) {
        if (tid == tids[i]) {
            return i;
        }
    }
    return -1;
}

int
execute_in_threads(
        int pid, uint64_t* tids, int count_tids, const char* python_code)
{
#if defined(__arm64__)
    int err = 0;
    kern_return_t kr = 0;
    enum { MAX_THREADS = 16 };
    struct tgt_thread thrds[MAX_THREADS] = {};
    mach_port_t exception_port = MACH_PORT_NULL;
    int found_threads = 0;
    struct handler_args args = {};

    if (count_tids < 0) {
        return ATT_FAIL;
    }
    if (count_tids > MAX_THREADS) {
        log_err("too many threads\n");
        return ATT_FAIL;
    }

    g_err = 0; // Have to restore this to 0  // XXX

    task_t task;
    if ((err = get_task(pid, &task)) != 0) {
        return err;
    }

    struct pyfn_addrs pyfn_addrs = {};
    if (find_needed_python_funcs(task, &pyfn_addrs) != 0) {
        return ATT_FAIL;
    }

    vm_address_t breakpoint_addr = pyfn_addrs.breakpoint_addr;

    for (int i = 0; i < count_tids; i++) {
        log_dbg("tids[i] = %"PRIu64"\n", tids[i]);
    }

    thread_act_array_t thread_list = NULL;
    mach_msg_type_number_t thread_count = 0;
    if ((kr = task_threads(task, &thread_list, &thread_count)) != KERN_SUCCESS) {
        log_mach("task_threads", kr);
    }

    for (int i = 0; i < (int)thread_count; i++) {
        struct thread_identifier_info info;
        __auto_type size = THREAD_IDENTIFIER_INFO_COUNT;
        __auto_type thread = thread_list[i];

        kr = thread_info((thread_inspect_t)thread,
                THREAD_IDENTIFIER_INFO, (thread_info_t)&info, &size);
        if (kr != 0) {
            log_mach("thread_info", kr);
            return ATT_FAIL;
        }

        if (-1 == find_tid(info.thread_id, tids, count_tids)) {
            continue;
        }
        __auto_type t = &thrds[found_threads++];
        t->thread_id = info.thread_id;
        t->act = thread;
        t->running = 1;
    }
    if (found_threads != count_tids) {
        // This could just mean that a thread died/completed between reporting
        // and us now looking.
        log_err("note: only %d of %d additional threads found", found_threads,
                count_tids);
    }

    for (int i = 0; i < found_threads; i++) {
        if ((kr = thread_suspend(thrds[i].act)) != KERN_SUCCESS) {
            log_mach("thread_suspend", kr);
            err = ATT_UNKNOWN_STATE;
            goto out;
        }
        thrds[i].running = 0;
    }

    for (int i = 0; i < found_threads; i++) {
        if ((err = set_hw_breakpoint(&thrds[i], breakpoint_addr))) {
            goto out;
        }
    }

    if (setup_exception_handling(task, &exception_port) != 0) {
        err = ATT_FAIL;
        goto out;
    }

    args = (struct handler_args) {
        .exc_type = HANDLE_HARDWARE,
        .python_code = (char*)python_code,
        .pyfn_addrs = pyfn_addrs,
        .count_threads = found_threads,
        .exc_port = exception_port,
    };
    if (init_handler_args(&args) != 0) {
        err = ATT_FAIL;
        goto out;
    }

    // TODO: validate python code length

    pthread_t s_exc_thread;
    if (pthread_create(&s_exc_thread, NULL, exception_server_thread,
            &args) != 0) {
        log_err("pthread_create");
        err = ATT_FAIL;
        goto out;
    }

    if ((kr = semaphore_wait(args.started)) != KERN_SUCCESS) {
        log_mach("waiting for pthread_create", kr);
        err = ATT_FAIL;
        goto out;
    }

    for (int i = 0; i < found_threads; i++) {
        log_dbg("resuming %d\n", thrds[i].act);
        if ((kr = thread_resume(thrds[i].act)) != KERN_SUCCESS) {
            log_mach("thread_resume", kr);
            err = ATT_UNKNOWN_STATE;
            goto out;
        }
        thrds[i].running = 1;
        thrds[i].attached = 1;
    }

    for (;;) {
        int count_attached = 0;
        for (int i = 0; i < found_threads; i++) {
            count_attached += thrds[i].attached;
        }
        log_dbg("count_attached = %d", count_attached);
        if (count_attached == 0) {
            break;
        }

        if (wait_for_probe_installation(args.completed, 30) != 0) {
            if (kr == KERN_OPERATION_TIMED_OUT) {
                log_err("timed out after 30s waiting to reach safe point");
            }
            err = atomic_load(&g_err);
            if (err == 0) { abort(); }; // bug in concurrency code.
            goto out;
        }
        log_dbg("last_completed = %d", args.last_completed->act);
        err = g_err;
        for (int i = 0; i < found_threads; i++) {
            if (thrds[i].act == args.last_completed->act) { // XXX: RACE
                thrds[i].attached = 0;
                thrds[i].hw_bp_set = 0;
            }
        }
        // XXX: we should have some sort of signaling back to the exc thread
        // here that it can continue or not
        if (err) {
            goto out;
        }
        atomic_store(&g_err, 0);
    }
    log_dbg("leaving...");

out:

    // Remove breakpoint
    for (int i = 0; i < found_threads; i++) {
        if (!thrds[i].hw_bp_set) {
            continue;
        }
        if (thrds[i].running) {
            if ((kr = thread_suspend(thrds[i].act)) != KERN_SUCCESS) {
                log_mach("thread_suspend", kr);
                err = ATT_UNKNOWN_STATE;
                continue;
            }
            thrds[i].running = 0;
        }
        if (remove_hw_breakpoint(&thrds[i])) {
            err = ATT_UNKNOWN_STATE;
        }
    }

    if (exception_port != MACH_PORT_NULL) {
        for (int i = 0; i < (int)old_exc_ports.count; i++) {
            kr = task_set_exception_ports(task,
                    old_exc_ports.masks[i],
                    old_exc_ports.ports[i],
                    old_exc_ports.behaviors[i],
                    old_exc_ports.flavors[i]);
            if (kr != KERN_SUCCESS) {
                log_mach("task_set_exception_ports", kr);
                err = ATT_UNKNOWN_STATE;
            }
        }
    }

    for (int i = 0; i < found_threads; i++) {
        if (thrds[i].running) {
            continue;
        }
        if ((kr = thread_resume(thrds[i].act)) != KERN_SUCCESS) {
            log_mach("thread_resume", kr);
            err = ATT_UNKNOWN_STATE;
        }
        thrds[i].running = 1;
    }

    /*
     * We clear up resources shared with the handler thread at the end, now
     * we hopefully have the thread up and running again and out of danger.
     */
    deinit_handler_args(&args);

    return err;
#else /* __x86_64__ */

    return -1; /* not implemented */
#endif /* __arm64__ */
}
