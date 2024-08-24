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

#if !defined(__arm64__)
#error "Platform not yet supported"
#endif

const bool debug = false;

// this does not seem to be called as often as I'd hoped
// maybe drop_gil is better...
//#define SAFE_POINT "PyErr_CheckSignals"
#define SAFE_POINT  "PyEval_SaveThread"

#define PYTHON_SO_BASENAME  "Python"

// this is what clang gives for __builtin_debugtrap()
//	brk	#0xf000
#define DEBUG_TRAP_INSTR    ((uint32_t)0xd43e0000)

static dispatch_semaphore_t sync_sema;

// Note we don't use atomic routines to set this when setting it
// just before using the semaphore.
static _Atomic int g_err; /* failure state from exc handler */

typedef struct {
    vm_address_t    page_addr;
    vm_size_t       pagesize;
    vm_offset_t     data; /* The entire page */
    vm_prot_t       protection;
} page_restore_t;

static page_restore_t g_breakpoint_restore;

static arm_thread_state64_t g_orig_threadstate;
static struct {
    vm_address_t addr;
    vm_size_t size;
} g_allocated;  /* page allocated to inject code into */


static struct {
    vm_address_t PyRun_SimpleString;
} g_pyfn_addrs;

static const char* g_python_code;
#define PYTHON_CODE_OFFSET  16

static vm_address_t find_pyfn(task_t task, const char* symbol);
static vm_address_t find_sysfn(task_t task, void* addr, const char* symbol);

/*
 * x16 must be set to the address of _write
 */
void injection();
void end_of_injection();
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

__attribute__((format(printf, 1, 2)))
static void
log_dbg(const char* fmt, ...)
{
    va_list valist;
    va_start(valist, fmt);

    if (debug) {
        fputs("[debug]: ", stderr);
        vfprintf(stderr, fmt, valist);
        if (fmt[strlen(fmt) - 1] != '\n') {
            fputs("\n", stderr);
        }
    }

    va_end(valist);
}

__attribute__((format(printf, 1, 2)))
static void
log_err(const char* fmt, ...)
{
    va_list valist;
    va_start(valist, fmt);
    int esaved = errno;

    fputs("attacher: ", stderr);
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
    mach_msg_type_number_t infoCnt = sizeof region_info;
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

// Adapted from https://gist.github.com/rodionovd/01fff61927a665d78ecf
static struct {
    mach_msg_type_number_t count;
    exception_mask_t      masks[TASK_MAX_EXCEPTION_PORT_COUNT];
    exception_handler_t   ports[TASK_MAX_EXCEPTION_PORT_COUNT];
    exception_behavior_t  behaviors[TASK_MAX_EXCEPTION_PORT_COUNT];
    thread_state_flavor_t flavors[TASK_MAX_EXCEPTION_PORT_COUNT];
} old_exc_ports;

static int
setup_exception_handling(task_t target_task, mach_port_t* exc_port)
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
        log_mach("mach_port_allocate", kr);
        return ATT_FAIL;
    }

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

    /* set the new exception ports */
    if ((kr = task_set_exception_ports(target_task, mask, *exc_port,
                    EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                    ARM_THREAD_STATE64)) != KERN_SUCCESS) {
        log_mach("task_set_exception_ports", kr);
        return ATT_FAIL;
    }
    return ATT_SUCCESS;
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

    log_dbg("in catch_exception_raise_state_identity");
    assert(exception == EXC_BREAKPOINT);
    assert(*flavor == ARM_THREAD_STATE64);
    assert(old_stateCnt == ARM_THREAD_STATE64_COUNT);

    if (debug) {
        __builtin_dump_struct((arm_thread_state64_t*)old_state, log_dbg);
    }

    // Copy old state to new state!
    memcpy(new_state, old_state, old_stateCnt * sizeof(natural_t));
    *new_stateCnt = old_stateCnt;

    arm_thread_state64_t* state = (arm_thread_state64_t*)new_state;

    __auto_type r = &g_breakpoint_restore;

    uint64_t pc = arm_thread_state64_get_pc(*state);
    if (pc >= r->page_addr && pc < r->page_addr + r->pagesize) {
        /*
         * Restore overwritten instruction
         */
        kr = restore_page(task, &g_breakpoint_restore);
        if (kr != KERN_SUCCESS) {
            log_mach("restore_page", kr);
            atomic_store(&g_err , ATT_UNKNOWN_STATE);
            dispatch_semaphore_signal(sync_sema);
            return KERN_FAILURE; /* I think it'll die anyway */
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

        vm_size_t pagesize = g_breakpoint_restore.pagesize;
        vm_address_t allocated = 0;
        kr = vm_allocate(task, &allocated, pagesize, true);
        if (kr != KERN_SUCCESS) {
            log_mach("vm_allocate", kr);
            g_err = ATT_FAIL; // technically we're leaking memory...
            dispatch_semaphore_signal(sync_sema);
            return KERN_SUCCESS;
        }
        /* save so we can deallocate at the end */
        g_allocated.addr = allocated;
        g_allocated.size = pagesize;

        // ... we could use malloc but this is the right size.
        vm_offset_t data;
        mach_msg_type_number_t dataCnt;
        if ((kr = vm_read(task, allocated, pagesize, &data, &dataCnt))
                != KERN_SUCCESS) {
            log_mach("vm_read", kr);
            g_err = ATT_FAIL;
            dispatch_semaphore_signal(sync_sema);
            return KERN_SUCCESS;
        }
        assert(dataCnt == pagesize);

        size_t inj_len = end_of_injection - injection;
        assert(inj_len <= PYTHON_CODE_OFFSET);
        memcpy((void*)data, injection, inj_len);

        const char* arg = g_python_code;
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
            dispatch_semaphore_signal(sync_sema);
            return KERN_SUCCESS;
        }

        /*
         * set up call
         */

        vm_address_t fn_addr = g_pyfn_addrs.PyRun_SimpleString;
        assert(fn_addr);

        g_orig_threadstate = *state;

        state->__x[0] = allocated + 16;
        state->__x[16] = fn_addr;
        arm_thread_state64_set_pc_fptr(*state, allocated);

    } else {
        /*
         * We've come back from PyRun_SimpleString
         */
        log_dbg("in the second breakpoint");
        assert(arm_thread_state64_get_pc(g_orig_threadstate) != 0);
        assert(g_allocated.addr != 0 && g_allocated.size != 0);

        uint64_t retval = state->__x[0];

        *(arm_thread_state64_t*)new_state = g_orig_threadstate;

        kr = vm_deallocate(task, g_allocated.addr, g_allocated.size);
        if (kr != KERN_SUCCESS) {
            log_mach("vm_deallocate", kr);
        }
        g_allocated.addr = g_allocated.size = 0;

        if (retval != 0) {
            log_err("PyRun_SimpleString failed (%d)", (int)retval);
        }
        g_err = (retval == 0) ? ATT_SUCCESS : ATT_FAIL;
        dispatch_semaphore_signal(sync_sema);
    }

    return KERN_SUCCESS;
}


extern boolean_t mach_exc_server(mach_msg_header_t *, mach_msg_header_t *);

static void *
exception_server_thread(void *arg)
{
    kern_return_t kr;
    mach_port_t exc_port = *(mach_port_t *)arg;

    // Signal thread started.
    dispatch_semaphore_signal(sync_sema);

    memset(&g_orig_threadstate, 0, sizeof g_orig_threadstate);

    /* Handle exceptions on exc_port */
    const int num_expected_break_points = 2;
    for (int i = 0; i < num_expected_break_points; i++){
        if ((kr = mach_msg_server_once(mach_exc_server, 4096, exc_port, 0))
                != KERN_SUCCESS) {
            log_mach("mach_msg_server", kr);
            break;
        }
    }
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

    for (;;) {
        int signo;
        errno = sigwait(&mask, &signo);
        if (errno != 0) {
            log_err("sigwait");
            exit(1);
        }
        if (signo == SIGUSR1) {
            // Used internally to shut down this thread.
            return NULL;
        } else {
            int expected = 0;
            if (atomic_compare_exchange_strong(&g_err, &expected,
                        ATT_INTERRUPTED)) {
                dispatch_semaphore_signal(sync_sema);
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

            Dl_info dlinfo = {};
            if (load_and_find_safepoint(it.filepath, symbol, &dlinfo) != 0) {
                continue;
            }
            log_dbg("found %s in %s", symbol, it.filepath);
            ptrdiff_t breakpoint_offset = dlinfo.dli_saddr - dlinfo.dli_fbase;

            fn_addr =
                (vm_address_t)it.info.imageLoadAddress + breakpoint_offset;
            break;
        }

    }
    errno = 0; // that search process above leaves the errno dirty
    return fn_addr;
}


static int
find_needed_python_funcs(task_t task)
{
    g_pyfn_addrs.PyRun_SimpleString = find_pyfn(task, "PyRun_SimpleString");
    if (!g_pyfn_addrs.PyRun_SimpleString) {
        log_err("could not find %s in shared libs", "PyRun_SimpleString");
        return ATT_FAIL;
    }
    return 0;
}


static int
wait_for_probe_installation(dispatch_semaphore_t sync_sema, int timeout_s)
{
    int err;

    __auto_type initial_timeout =
        dispatch_time(DISPATCH_TIME_NOW, timeout_s * NSEC_PER_SEC);
    __auto_type timeout2 = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);

    err = dispatch_semaphore_wait(sync_sema, initial_timeout);
    if (err != 0) {
        int expected = 0;
        if (!atomic_compare_exchange_strong(&g_err, &expected,
                    ATT_INTERRUPTED)) {
            fprintf(stderr, "Waiting 10s more as it seems we're making "
                    "progress\n");
            if (0 == dispatch_semaphore_wait(sync_sema, timeout2)) {
                return 0;
            }
        }
        return err;
    }
    return 0;
}


int
attach_and_execute(const int pid, const char* python_code)
{
    int err = 0;

    // TODO: This code is hilariously non-reentrant. Find a way to
    // protect it. or make it reentrant.

    g_err = 0; // Have to restore this to 0

    task_t task = TASK_NULL;
    kern_return_t kr;
    if ((kr = task_for_pid(mach_task_self(), pid, &task)) != KERN_SUCCESS) {
        log_mach("task_for_pid", kr);
        return ATT_FAIL;
    }
    assert(task != TASK_NULL);

    vm_size_t pagesize = 0;
    if ((kr = host_page_size(mach_host_self(), &pagesize)) != KERN_SUCCESS) {
        log_mach("host_page_size", kr);
        return ATT_FAIL;
    }
    assert(pagesize != 0);

    if (PYTHON_CODE_OFFSET + strlen(python_code) + 1 > pagesize) {
        log_err("python code exceeds max size: %lu\n",
                pagesize - PYTHON_CODE_OFFSET - 1);
        return ATT_FAIL;
    }

    // Find some python fn addresses in advance of playing around with
    // setting breakpoints.
    if (find_needed_python_funcs(task) != 0) {
        return ATT_FAIL;
    }

    vm_address_t breakpoint_addr = find_pyfn(task, SAFE_POINT);
    if (breakpoint_addr == 0) {
        log_err("%s not found in target libraries\n", SAFE_POINT);
        return ATT_FAIL;
    }
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
    *(uint32_t*)local_bp_addr = DEBUG_TRAP_INSTR;


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


    sync_sema = dispatch_semaphore_create(0);
    if (!sync_sema) {
        log_err("dispatch_semaphore_create");
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
                    0)) != 0) {
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

    /* Set global before creating the exc thread, means no need to sync */
    g_breakpoint_restore = page_restore;
    g_python_code = python_code;

    mach_port_t exception_port = MACH_PORT_NULL;

    if (setup_exception_handling(task, &exception_port) != 0) {
        err = ATT_FAIL;
        if (restore_page(task, &page_restore) != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        goto restore_mask;
    }


    pthread_t s_exc_thread;
    if (pthread_create(&s_exc_thread, NULL, exception_server_thread,
            &exception_port) != 0) {
        log_err("pthread_create");
        err = ATT_FAIL;
        if (restore_page(task, &page_restore) != KERN_SUCCESS) {
            err = ATT_UNKNOWN_STATE;
        }
        goto out;
    }

    if (dispatch_semaphore_wait(sync_sema,
                    dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) != 0) {
        log_err("timed out after 2s waiting for pthread_create");
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

    if (wait_for_probe_installation(sync_sema, 30) != 0) {
        kr = suspend_and_restore_page(task, &g_breakpoint_restore);
        log_err("timed out after 30s waiting to reach safe point");
        err = atomic_load(&g_err);
        if (err == 0) { abort(); }; // bug in concurrency code.
        if (kr != KERN_SUCCESS) {
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
        kr = suspend_and_restore_page(task, &g_breakpoint_restore);
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
        // We're leaving our process in an inconsistent state. We should die!
        log_err("pthread_sigmask");
        exit(1);
    }
    if (sync_sema) {
        dispatch_release(sync_sema);
        sync_sema = NULL;
    }

    return err;
}
