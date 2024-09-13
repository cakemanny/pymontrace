#include <sys/types.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/time.h>

#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach/mach_param.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <execinfo.h>
#include <libgen.h>
#include <signal.h>
#include <unistd.h>


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
    mach_port_t exc_port;
    bool interrupted;   /* we've been interrupted. the target should be
                           restored to what it was doing.*/
};

/*
 * The handler thread keeps it's own threadlocal copy of it's args
 * in order to pass across the mach_msg_server boundary
 */
static __thread struct handler_args t_handler_args;

/*
 * About what happened during the most recent exception handler.
 */
struct handler_result {
    kern_return_t kr;   /* result returned implies target death or not */
    thread_act_t act;   /* the thread_act the exception was for */
    int err;    /* whether successful */
    enum {
        BPK_AT_SAFE_POINT = 0,
        BPK_AFTER_PYRUN = 1,
    } bp_kind; /*  */
};

static __thread struct handler_result t_handler_result;

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

#define log_odbg(fmt, v)    log_dbg(#v " = " fmt, v)

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

static int
set_hw_breakpoint(struct tgt_thread* thrd, uintptr_t bp_addr)
{
    kern_return_t kr;

    __auto_type thread = thrd->act;
#if defined(__arm64__)
    arm_debug_state64_t debug_state = {};
    __auto_type stateCnt = ARM_DEBUG_STATE64_COUNT;
    int flavor = ARM_DEBUG_STATE64;
#elif defined(__x86_64__)
    x86_debug_state64_t debug_state = {};
    __auto_type stateCnt = x86_DEBUG_STATE64_COUNT;
    int flavor = x86_DEBUG_STATE64;
#endif /* __arm64__ */

    if ((kr = thread_get_state(thread, flavor,
                    (thread_state_t)&debug_state, &stateCnt)) != 0) {
        log_mach("thread_get_state", kr);
        return ATT_FAIL;
    }

#if defined(__arm64__)

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

#elif defined(__x86_64__)

    if (debug_state.__dr0 != 0) {
        log_err("debug registers in use");
        return ATT_FAIL;
    }

    int dr_idx = 0;  // will change if we ever decide to probe for free reg.

    uint64_t ctrl = debug_state.__dr7;
    // See linux code for comments
    ctrl |= (1 << (2 * dr_idx));
    ctrl &= ~((0b1111 << (dr_idx * 4)) << 16);

    debug_state.__dr0 = bp_addr;
    debug_state.__dr7 = ctrl;

#endif /* __arm64__ */

    if ((kr = thread_set_state(thread, flavor,
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
#if defined(__arm64__)
    arm_debug_state64_t debug_state = {};
    __auto_type stateCnt = ARM_DEBUG_STATE64_COUNT;
    int flavor = ARM_DEBUG_STATE64;
#elif defined(__x86_64__)
    x86_debug_state64_t debug_state = {};
    __auto_type stateCnt = x86_DEBUG_STATE64_COUNT;
    int flavor = x86_DEBUG_STATE64;
#endif /* __arm64__ */

    if ((kr = thread_get_state(thread, flavor,
                    (thread_state_t)&debug_state, &stateCnt)) != 0) {
        log_mach("thread_get_state", kr);
        return ATT_FAIL;
    }

#if defined(__arm64__)

    if (debug_state.__bvr[0] == 0 && debug_state.__bcr[0] == 0) {
        log_err("hw bp not set :/");
        thrd->hw_bp_set = 0;
        return 0;
    }

    debug_state.__bcr[0] = 0ULL;
    debug_state.__bvr[0] = 0ULL;

#elif defined(__x86_64__)

    if (debug_state.__dr0 == 0) {
        log_err("hw bp not set :/");
        thrd->hw_bp_set = 0;
        return 0;
    }

    int dr_idx = 0;
    // Clear local enable bit. See linux code for better comments.
    debug_state.__dr7 &= ~(1 << (2 * dr_idx));
    debug_state.__dr0 = 0;

#endif /* __arm64__ */

    if ((kr = thread_set_state(thread, flavor,
                       (thread_state_t)&debug_state, stateCnt)) != 0) {
        log_mach("thread_set_state", kr);
        return ATT_FAIL;
    }
    thrd->hw_bp_set = 0;
    return 0;
}


#ifdef __arm64__
static int
get_exception_type(thread_act_t thread, int* exc_type)
{
    kern_return_t kr;
    arm_exception_state64_t exc_state;
    __auto_type exc_stateCnt = ARM_EXCEPTION_STATE64_COUNT;
    if ((kr = thread_get_state(thread, ARM_EXCEPTION_STATE64,
                    (thread_state_t)&exc_state, &exc_stateCnt))) {
        log_mach("thread_get_state exc state", kr);
        return ATT_FAIL;
    }

    __auto_type exception_class = (exc_state.__esr >> 26) & 0b111111;
    switch (exception_class) {
        case 0b110000: // Breakpoint exception from a lower Exception level
        case 0b110001: // Breakpoint exception taken without a change in Exception level.
            *exc_type = HANDLE_HARDWARE;
            return 0;
        case 0b111000: // BRK instruction execution in AArch32 state
        case 0b111100: // BRK instruction execution in AArch64 state
            *exc_type = HANDLE_SOFTWARE;
            return 0;
        default:
            log_err("unknown exception class 0x%x", exception_class);
            return ATT_FAIL;
    }
}
#endif


// backport for macOS < 14
#ifndef TASK_MAX_EXCEPTION_PORT_COUNT
#define TASK_MAX_EXCEPTION_PORT_COUNT EXC_TYPES_COUNT
#endif // TASK_MAX_EXCEPTION_PORT_COUNT

// Adapted from https://gist.github.com/rodionovd/01fff61927a665d78ecf
struct old_exc_ports {
    mach_msg_type_number_t count;
    exception_mask_t      masks[TASK_MAX_EXCEPTION_PORT_COUNT];
    exception_handler_t   ports[TASK_MAX_EXCEPTION_PORT_COUNT];
    exception_behavior_t  behaviors[TASK_MAX_EXCEPTION_PORT_COUNT];
    thread_state_flavor_t flavors[TASK_MAX_EXCEPTION_PORT_COUNT];
};

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
setup_exception_handling(
        task_t target_task, mach_port_t* exc_port, struct old_exc_ports* old)
{
    kern_return_t kr = 0;
    int err;

    if ((err = prepare_exc_port(exc_port)) != 0) {
        return err;
    }

    old->count = TASK_MAX_EXCEPTION_PORT_COUNT;

    exception_mask_t mask = EXC_MASK_BREAKPOINT;

    /* get the old exception ports */
    if ((kr = task_get_exception_ports(target_task, mask, old->masks,
                    &old->count, old->ports, old->behaviors, old->flavors))
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

static int
restore_exception_handling(
        task_t target_task, struct old_exc_ports* old)
{
    kern_return_t kr;
    int err = 0;

    log_dbg("old->count = %d", old->count);
    for (int i = 0; i < (int)old->count; i++) {
        kr = task_set_exception_ports(target_task, old->masks[i],
                old->ports[i], old->behaviors[i], old->flavors[i]);
        if (kr != KERN_SUCCESS) {
            log_mach("task_set_exception_ports", kr);
            err = ATT_UNKNOWN_STATE;
        }
    }
    return err;
}

__attribute__((unused))
static int
setup_thread_exc_handling(thread_act_t thread, mach_port_t* exc_port,
        struct old_exc_port* old)
{
    kern_return_t kr = 0;

    exception_mask_t mask = EXC_MASK_BREAKPOINT;
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

static inline void
print_backtrace()
{
    void* callstack[128];
    int frames = backtrace(callstack, 128);
    backtrace_symbols_fd(callstack, frames, STDERR_FILENO);
}

void
sem_signal(semaphore_t semaphore)
{
    kern_return_t kr = 0;
    if ((kr = semaphore_signal(semaphore)) != KERN_SUCCESS) {
        log_mach("semaphore_signal", kr);
        if (debug) {
            print_backtrace();
        }
    }
}

static inline kern_return_t
handler_result(
        kern_return_t kr, thread_act_t act, int err, int bp_kind)
{
    t_handler_result.kr = kr;
    t_handler_result.act = act;
    t_handler_result.err = err;
    t_handler_result.bp_kind = bp_kind;
    return kr;
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
    if (codeCnt >= 2) {
        log_dbg("code[0] = 0x%llx, code[1] = 0x%llx", code[0], code[1]);
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
        log_dbg("pc = %llx", pc);
        int bp_kind = BPK_AT_SAFE_POINT;

#ifdef __arm64__
        int exc_type = 0;
        if (get_exception_type(thread, &exc_type) != 0) {
            return handler_result(KERN_FAILURE, thread, ATT_UNKNOWN_STATE,
                    bp_kind); /* I think it'll die anyway */
        }
#endif

        if (handler->exc_type == HANDLE_SOFTWARE) {
            if (handler->breakpoint_restore.page_addr == 0) {
                abort();
            }
#ifdef __arm64__
            if (exc_type != HANDLE_SOFTWARE) {
                log_err("leaked hw exception");
                abort();
            }
#endif

            /*
             * Restore overwritten instruction
             */
            kr = task_suspend(task); // hopefully this forces rereading the code?
            if (kr) log_mach("task_suspend", kr);
            kr = restore_page(task, &handler->breakpoint_restore);
            kern_return_t kr2 = task_resume(task);
            if (kr2) log_mach("task_resume", kr);
            if (kr != KERN_SUCCESS) {
                log_mach("restore_page", kr);
                return handler_result(KERN_FAILURE, thread, ATT_UNKNOWN_STATE,
                    bp_kind); /* I think it'll die anyway */
            }
        } else {
            assert(handler->exc_type == HANDLE_HARDWARE);
#ifdef __arm64__
            if (exc_type != HANDLE_HARDWARE) {
                log_err("leaked sw exception");
                abort();
            }
#endif
            struct tgt_thread thrd = { .act = thread, };
            int err = remove_hw_breakpoint(&thrd);
            if (err != 0) {
                return handler_result(KERN_FAILURE, thread, ATT_UNKNOWN_STATE,
                    bp_kind);
            }
        }

        // This is our last chance to bail.
        if (handler->interrupted) {
            // Either the timeout or a signal beat us but wasn't finished
            // restoring the page. They can still continue though.
            return handler_result(
                    KERN_SUCCESS, thread, ATT_INTERRUPTED, bp_kind);
        }

        /* copy in code and data for hijack */

        vm_size_t pagesize = getpagesize();
        vm_address_t allocated = 0;
        kr = vm_allocate(task, &allocated, pagesize, true);
        if (kr != KERN_SUCCESS) {
            log_mach("vm_allocate", kr);
            // technically we're leaking memory...
            return handler_result(KERN_SUCCESS, thread, ATT_FAIL, bp_kind);
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
            return handler_result(KERN_SUCCESS, thread, ATT_FAIL, bp_kind);
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
            return handler_result(KERN_SUCCESS, thread, ATT_FAIL, bp_kind);
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

        return handler_result(KERN_SUCCESS, thread, ATT_SUCCESS,
                BPK_AT_SAFE_POINT);
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
        memset(state_slot, 0, sizeof *state_slot);

        if (retval != 0) {
            log_err("PyRun_SimpleString failed (%d)", (int)retval);
        }
        int err = (retval == 0) ? ATT_SUCCESS : ATT_FAIL;

        return handler_result(KERN_SUCCESS, thread, err, BPK_AFTER_PYRUN);
    }
}

/*
 * This is implemented by the mig generated code in mach_excServer.c
 */
extern boolean_t mach_exc_server(mach_msg_header_t *, mach_msg_header_t *);

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
    // FIXME: we should pause the task before doing this, in order to
    // get a consistent read

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
attach_and_execute(const int pid, const char* python_code)
{
    int err = 0;
    kern_return_t kr;
    struct handler_args args = {};
    struct old_exc_ports old_exc_ports = {};
    int kq = -1; /* kqueue file descriptor */

    // TODO: This code is hilariously non-reentrant. Find a way to
    // protect it. or make it reentrant.

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

    /*
     * Now we enter the critical section, so we block signals until
     * we've set things up and are in a good state to reverse them
     * on a ctrl-c
     */
    sigset_t old_mask = 0;
    sigset_t signal_mask = init_signal_mask();
    if ((errno = sigprocmask(SIG_BLOCK, &signal_mask, &old_mask)) != 0) {
        log_err("pthread_sigmask");
        return ATT_FAIL;
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

    if (setup_exception_handling(task, &exception_port, &old_exc_ports) != 0) {
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
    args.exc_port = exception_port;

    /* copy the args into our thread local space */
    t_handler_args = args;

    if (-1 == (kq = kqueue())) {
        log_err("kqueue");
        err = ATT_FAIL;
        if (restore_page(task, &page_restore) != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        goto out;
    }

    struct kevent64_s kev[] = {
        {
            .ident = exception_port,
            .filter = EVFILT_MACHPORT,
            .flags = EV_ADD,
        },
        {
            .ident = SIGHUP,
            .filter = EVFILT_SIGNAL,
            .flags = EV_ADD,
        },
        {
            .ident = SIGINT,
            .filter = EVFILT_SIGNAL,
            .flags = EV_ADD,
        },
        {
            .ident = SIGTERM,
            .filter = EVFILT_SIGNAL,
            .flags = EV_ADD,
        },
        {
            .ident = SIGQUIT,
            .filter = EVFILT_SIGNAL,
            .flags = EV_ADD,
        },
    };
    int nevents = kevent64(kq, kev, NELEMS(kev), NULL, 0, 0, NULL);
    if (nevents == -1) {
        log_err("kevent64");
        err = ATT_FAIL;
        if (restore_page(task, &page_restore) != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        goto out;
    }
    assert(nevents == 0);


    fprintf(stderr, "Waiting for process to reach safepoint...\n");
    if ((kr = task_resume(task)) != KERN_SUCCESS) {
        log_mach("task_resume", kr);
        err = ATT_FAIL;
        if (restore_page(task, &page_restore) != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        goto out;
    }

    bool page_restored = false;
    bool code_execd = false;
    for (;;) {
        if (code_execd) {
            break;
        }

        struct kevent64_s eventlist[1] = {};
        struct timespec timeout = { .tv_sec = 30, };
        nevents = kevent64(kq, NULL, 0, eventlist, 1, 0, &timeout);
        if (-1 == nevents) {
            int esaved = errno;
            kr = KERN_SUCCESS;
            if (!page_restored) {
                kr = suspend_and_restore_page(task, &page_restore);
            }
            errno = esaved;
            if (errno == EINTR) {
                log_err("interrupted waiting to reach safe point");
                err = ATT_INTERRUPTED;
            } else {
                log_err("kevent64");
                err = ATT_FAIL;
            }
            if (kr != KERN_SUCCESS) {
                err = ATT_UNKNOWN_STATE;
            }
            // It seems like here, we are forgetting to resume the task...

            // Assuming no race with the exception handler, we're back to original
            // state.
            // TODO: do a non-blocking mach exception check to ensure we're
            // not leaving the process about to die.
            goto out;
        } else if (nevents == 0) {
            log_err("timed out after 30s waiting to reach safe point");
            err = ATT_INTERRUPTED;
            goto out;
        }

        if (eventlist[0].filter == EVFILT_MACHPORT) {
            assert(eventlist[0].filter == EVFILT_MACHPORT);

            // Shouldn't need MACH_RCV_INTERRUPT or a timeout in theory
            if ((kr = mach_msg_server_once(mach_exc_server,
                            MACH_MSG_SIZE_RELIABLE, args.exc_port, 0))
                    != KERN_SUCCESS) {
                log_mach("mach_msg_server_once", kr);
                // ??
                err = ATT_UNKNOWN_STATE;
                goto out;
            }

            // check error code set in the exception handler.
            err = t_handler_result.err;
            if (t_handler_result.kr == KERN_FAILURE) {
                goto out;
            }
            switch (t_handler_result.bp_kind) {
                case BPK_AT_SAFE_POINT:
                    page_restored = true;
                    break;
                case BPK_AFTER_PYRUN:
                    code_execd = true;
                    break;
            }
        } else if (eventlist[0].filter == EVFILT_SIGNAL) {
            if (!page_restored) {
                err = ATT_INTERRUPTED;
                // TODO: set handler.interrupted and run the
                // mach_msg_server_once in a non-blocking manner.
            } else {
                fprintf(stderr,
                        "Hold on a mo, we're in the middle of surgery. "
                        "Will be done in a few seconds.\n");
                continue;
            }
        }

        if (err == ATT_INTERRUPTED) {
            if (!page_restored) {
                kr = suspend_and_restore_page(task, &page_restore);
                if (kr != KERN_SUCCESS) {
                    err = ATT_UNKNOWN_STATE;
                } else {
                    fprintf(stderr, "Cancelled\n");
                }
            }
        }
        if (err) {
            goto out;
        }
    }


out:
    if (kq != -1) {
        close(kq);
    }

    // Right now, this doesn't deal with the possibility of the task
    // having ended for whatever reason.
    if (exception_port != MACH_PORT_NULL) {
        if (restore_exception_handling(task, &old_exc_ports) != 0) {
            err = ATT_UNKNOWN_STATE;
        }
        if ((kr = mach_port_deallocate(mach_task_self(), exception_port))) {
            log_mach("mach_port_deallocate", kr);
        }
    }

restore_mask:
    if ((errno = sigprocmask(SIG_SETMASK, &old_mask, NULL))) {
        log_err("BUG: pthread_sigmask");
        abort();  // can only be EINVAL
    }
    return err;
}

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
    int err = 0;
    kern_return_t kr = 0;
    enum { MAX_THREADS = 16 };
    struct tgt_thread thrds[MAX_THREADS] = {};
    mach_port_t exception_port = MACH_PORT_NULL;
    int found_threads = 0;
    struct handler_args args = {};
    struct old_exc_ports old_exc_ports = {};
    int kq = -1; /* kqueue file descriptor */

    if (count_tids < 0) {
        return ATT_FAIL;
    }
    if (count_tids > MAX_THREADS) {
        log_err("too many threads\n");
        return ATT_FAIL;
    }

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

    // TODO: suspend the target task while gathering the thread information

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
        log_err("note: only %d of %d additional threads found\n", found_threads,
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

    if (setup_exception_handling(task, &exception_port, &old_exc_ports) != 0) {
        err = ATT_FAIL;
        goto out;
    }

    args = (struct handler_args) {
        .exc_type = HANDLE_HARDWARE,
        .python_code = (char*)python_code,
        .pyfn_addrs = pyfn_addrs,
        .exc_port = exception_port,
    };
    /* copy the args into our thread local space */
    t_handler_args = args;

    // TODO: validate python code length

    if (-1 == (kq = kqueue())) {
        log_err("kqueue");
        err = ATT_FAIL;
        goto out;
    }
    struct kevent64_s kev = {
        .ident = exception_port,
        .filter = EVFILT_MACHPORT,
        .flags = EV_ADD,
    };
    int nevents = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
    if (nevents == -1) {
        log_err("kevent64");
        err = ATT_FAIL;
        goto out;
    }
    assert(nevents == 0);

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

        struct kevent64_s eventlist[1] = {};
        struct timespec timeout = { .tv_sec = 30, };
        nevents = kevent64(kq, NULL, 0, eventlist, 1, 0, &timeout);
        if (-1 == nevents) {
            if (errno == EINTR) {
                err = ATT_INTERRUPTED;
            } else {
                err = ATT_FAIL;
            }
            log_err("kevent64");
            goto out;
        } else if (nevents == 0) {
                log_err("timed out after 30s waiting to reach safe point");
            err = ATT_INTERRUPTED;
            goto out;
        }

        assert(eventlist[0].filter == EVFILT_MACHPORT);
        mach_port_t port = eventlist[0].data;

        if ((kr = mach_msg_server_once(mach_exc_server,
                        MACH_MSG_SIZE_RELIABLE, port, 0))
                != KERN_SUCCESS) {
            log_mach("mach_msg_server_once", kr);
            // ??
            err = ATT_UNKNOWN_STATE;
            goto out;
        }

        err = t_handler_result.err;
        if (t_handler_result.kr == KERN_FAILURE) {
            goto out;
        }

        for (int i = 0; i < found_threads; i++) {
            if (thrds[i].act == t_handler_result.act) {
                switch (t_handler_result.bp_kind) {
                case BPK_AT_SAFE_POINT:
                    thrds[i].hw_bp_set = 0;
                    break;
                case BPK_AFTER_PYRUN:
                    thrds[i].attached = 0;
                    break;
                }
            }
        }

        if (err) {
            goto out;
        }
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

    if (kq != -1) {
        close(kq);
    }

    if (exception_port != MACH_PORT_NULL) {
        if (restore_exception_handling(task, &old_exc_ports) != 0) {
            err = ATT_UNKNOWN_STATE;
        }
        if ((kr = mach_port_deallocate(mach_task_self(), exception_port))) {
            log_mach("mach_port_deallocate", kr);
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

    return err;
}
