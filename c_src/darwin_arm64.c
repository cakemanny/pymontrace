#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include <dlfcn.h>
#include <pthread.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>

#include <dispatch/dispatch.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach/mach_param.h>

#include <assert.h>

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
#define DEBUG_TRAP_INSTR    0xd43e0000

static dispatch_semaphore_t sync_sema;

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
	.p2align	2\n\
	.global _end_of_injection\n\
_end_of_injection:\n\
	b	_injection\n\
");


static void
fatal(const char* msg)
{
    if (errno != 0) {
        int esaved = errno;
        fputs("attacher: ", stderr);
        errno = esaved;
        perror(msg);
    } else {
        fprintf(stderr, "attacher: %s\n", msg);
    }
    exit(1);
}
static void
log_mach(const char* msg, kern_return_t kr)
{
    fprintf(stderr, "attacher: %s: %s (%d)\n", msg, mach_error_string(kr), kr);
}
static void
fatal_mach(const char* msg, kern_return_t kr)
{
    log_mach(msg, kr);
    exit(1);
}

static int
load_and_find_safepoint(const char* sopath, const char* symbol, Dl_info* info)
{
    void* handle = dlopen(sopath, RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "attacher: %s\n", dlerror());
        return 1;
    }

    void* faddr = dlsym(handle, symbol);
    if (faddr == NULL) {
        return 1;
    }

    if (dladdr(faddr, info) == 0) { // yes, 0 means failure for dladdr
        fprintf(stderr, "attacher: %s\n", dlerror());
        info = NULL;
        return 1;
    }
    assert(strcmp(info->dli_sname, symbol) == 0);
    if (strcmp(info->dli_fname, sopath) != 0) {
        fprintf(stderr, "info->dli_fname = %s\n", info->dli_fname);
        fprintf(stderr, "         sopath = %s\n", sopath);
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

static void
setup_exception_handling(task_t target_task, mach_port_t* exc_port)
{
    kern_return_t kr = 0;
    mach_port_t me = mach_task_self();
    if ((kr = mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE, exc_port))
            != KERN_SUCCESS) {
        fatal_mach("mach_port_allocate", kr);
    }
    if ((kr = mach_port_insert_right(me, *exc_port, *exc_port,
                    MACH_MSG_TYPE_MAKE_SEND)) != KERN_SUCCESS) {
        fatal_mach("mach_port_allocate", kr);
    }

    exception_mask_t mask = EXC_MASK_BREAKPOINT;
    /* get the old exception ports */
    if ((kr = task_get_exception_ports(
                    target_task, mask, old_exc_ports.masks,
                    &old_exc_ports.count, old_exc_ports.ports,
                    old_exc_ports.behaviors, old_exc_ports.flavors))
            != KERN_SUCCESS) {
        fatal_mach("task_get_exception_ports", kr);
    }

    /* set the new exception ports */
    if ((kr = task_set_exception_ports(target_task, mask, *exc_port,
                    EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                    ARM_THREAD_STATE64)) != KERN_SUCCESS) {
        fatal_mach("task_set_exception_ports", kr);
    }
}


extern kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
        mach_port_t thread,
        mach_port_t task,
        exception_type_t exception,
        mach_exception_data_t code,
        mach_msg_type_number_t code_count)
{
    fprintf(stderr, "unexected call: catch_mach_exception_raise\n");
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
    fprintf(stderr, "unexected call: catch_mach_exception_raise_state\n");
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

    if (debug) { fprintf(stderr, "in catch_exception_raise_state_identity\n"); }
    assert(exception == EXC_BREAKPOINT);
    assert(*flavor == ARM_THREAD_STATE64);
    assert(old_stateCnt == ARM_THREAD_STATE64_COUNT);

    arm_thread_state64_t* state = (arm_thread_state64_t*)old_state;
    if (debug) { __builtin_dump_struct(state, printf); }

    // copy old state to new state!
    *(arm_thread_state64_t*)new_state = *state;
    *new_stateCnt = old_stateCnt;

    __auto_type r = &g_breakpoint_restore;

    uint64_t pc = arm_thread_state64_get_pc(*state);
    if (pc >= r->page_addr && pc < r->page_addr + r->pagesize) {
        // TODO: we should take some sort of lock to avoid a race condition
        // with the timeout code.
        /*
         * Restore overwritten instruction
         */
        kr = restore_page(task, &g_breakpoint_restore);
        if (kr != KERN_SUCCESS) {
            fatal_mach("restore_page", kr);
        }

        /* copy in code and data for hijack */

        vm_size_t pagesize = g_breakpoint_restore.pagesize;
        vm_address_t allocated = 0;
        kr = vm_allocate(task, &allocated, pagesize, true);
        if (kr != KERN_SUCCESS) {
            fatal_mach("vm_allocate", kr);
        }
        /* save so we can deallocate at the end */
        g_allocated.addr = allocated;
        g_allocated.size = pagesize;

        // ... we could use malloc but this is the right size.
        vm_offset_t data;
        mach_msg_type_number_t dataCnt;
        if ((kr = vm_read(task, allocated, pagesize, &data, &dataCnt))
                != KERN_SUCCESS) {
            fatal_mach("vm_read", kr);
        }
        assert(dataCnt == pagesize);

        size_t inj_len = (char*)end_of_injection - (char*)injection;
        assert(inj_len <= PYTHON_CODE_OFFSET);
        memcpy((void*)data, injection, inj_len);

        assert(g_allocated != NULL);
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
        restore_page(task, &page_restore);

        /*
         * set up call
         */

        vm_address_t fn_addr = find_pyfn(task, "PyRun_SimpleString");
        if (!fn_addr) {
            fatal("find_sysfn");
        }

        g_orig_threadstate = *state;

        arm_thread_state64_t* state = (arm_thread_state64_t*)new_state;

        // we're gonna die!
        state->__x[0] = allocated + 16;
        state->__x[16] = fn_addr;
        arm_thread_state64_set_pc_fptr(*state, allocated);

    } else {
        if (debug) { fprintf(stderr, "in the second breakpoint\n"); }
        assert(arm_thread_state64_get_pc(g_orig_threadstate) != 0);
        assert(g_allocated.addr != 0 && g_allocated.size != 0);

        *(arm_thread_state64_t*)new_state = g_orig_threadstate;

        kr = vm_deallocate(task, g_allocated.addr, g_allocated.size);
        if (kr != KERN_SUCCESS) {
            log_mach("vm_deallocate", kr);
        }

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

    dispatch_semaphore_signal(sync_sema);
    /* Handle exceptions on exc_port */
    if ((kr = mach_msg_server(mach_exc_server, 4096, exc_port, 0))
            != KERN_SUCCESS) {
        fatal_mach("mach_msg_server", kr);
    }
    return NULL;
}

// Find write or PyRun_SimpleString

struct dyld_image_info_it {
    struct dyld_all_image_infos infos;
    struct dyld_image_info info;
    char filepath[1024];
    int idx;
};

static void
iter_dyld_infos(task_t task, struct dyld_image_info_it* it)
{
    kern_return_t kr = 0;

    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if ((kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count))
            != KERN_SUCCESS) {
        fatal_mach("task_info", kr);
    }

    assert(it->infos.infoArrayCount == 0);

    vm_size_t outsize = 0;
    if ((kr = vm_read_overwrite(task, dyld_info.all_image_info_addr,
                    sizeof it->infos, (vm_address_t)&it->infos, &outsize))
            != KERN_SUCCESS) {
        fatal_mach("vm_read_overwrite", kr);
    }
    assert(it->infos.infoArrayCount <= 1000);

    if (it->infos.infoArray == NULL) {
        // TODO: sleep-wait
        fatal("dyld_all_image_infos is being modified.");
    }
}

static bool
iter_dyld_infos_next(task_t task, struct dyld_image_info_it* it)
{
    kern_return_t kr;
    int i = it->idx;
    if (!(i < it->infos.infoArrayCount)) {
        return false;
    }

    vm_size_t outsize = 0;

    kr = vm_read_overwrite(task, (vm_address_t)&it->infos.infoArray[i],
            sizeof it->info, (vm_address_t)&it->info, &outsize);
    if (kr != KERN_SUCCESS) {
        fatal_mach("vm_read_overwrite", kr);
    }
    assert(outsize >= sizeof it->info);

    kr = vm_read_overwrite(task, (vm_address_t)it->info.imageFilePath,
                    sizeof it->filepath, (vm_address_t)it->filepath, &outsize);
    if (kr != KERN_SUCCESS) {
        fatal_mach("vm_read_overwrite", kr);
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
        fatal("dladdr");
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
            if (debug) {
                fprintf(stderr, "found %s in %s\n", symbol, it.filepath);
            }
            ptrdiff_t breakpoint_offset = dlinfo.dli_saddr - dlinfo.dli_fbase;

            fn_addr =
                (vm_address_t)it.info.imageLoadAddress + breakpoint_offset;
            break;
        }

    }
    errno = 0; // that search process above leaves the errno dirty
    return fn_addr;
}


int
attach_and_execute(int pid, const char* python_code)
{
    task_t task = TASK_NULL;
    kern_return_t kr;
    if ((kr = task_for_pid(mach_task_self(), pid, &task)) != KERN_SUCCESS) {
        fatal_mach("task_for_pid", kr);
    }
    assert(task != TASK_NULL);

    vm_size_t pagesize = 0;
    if ((kr = host_page_size(mach_host_self(), &pagesize)) != KERN_SUCCESS) {
        fatal_mach("host_page_size", kr);
    }
    assert(pagesize != 0);

    if (PYTHON_CODE_OFFSET + strlen(python_code) + 1 > pagesize) {
        fprintf(stderr, "python code exceeds max size: %lu",
                pagesize - PYTHON_CODE_OFFSET - 1);
        return -1;
    }

    vm_address_t breakpoint_addr = find_pyfn(task, SAFE_POINT);
    if (breakpoint_addr == 0) {
        fatal(SAFE_POINT " not found in target libraries");
    }
    if (debug) {
        fprintf(stderr, SAFE_POINT " is at %p in process %d\n",
                (void*)breakpoint_addr, pid);
    }


    // work out page to read and write

    vm_address_t page_boundary = breakpoint_addr & ~(pagesize - 1);
    vm_offset_t bp_page_offset = breakpoint_addr & (pagesize - 1);

    // Attach and set breakpoint
    if ((kr = task_suspend(task)) != KERN_SUCCESS) {
        fatal_mach("task_suspend", kr);
    }

    vm_offset_t data;
    mach_msg_type_number_t dataCnt;
    if ((kr = vm_read(task, page_boundary, pagesize, &data, &dataCnt))
            != KERN_SUCCESS) {
        fatal_mach("vm_read", kr);
    }
    assert(dataCnt == pagesize);
    void* local_bp_addr = (char*)data + (ptrdiff_t)bp_page_offset;

    uint32_t saved_instruction = *(uint32_t*)local_bp_addr;
    if (debug) { fprintf(stderr, "instr at BP: %8x\n", saved_instruction); }

    /* write the breakpoint */
    *(uint32_t*)local_bp_addr = DEBUG_TRAP_INSTR;


    int protection;
    kr = get_region_protection(task, page_boundary, &protection);
    if (kr != KERN_SUCCESS) {
        fatal_mach("get_region_protection", kr);
    }

    if (debug) {
        char prot_str[4];
        fmt_prot(prot_str, protection);
        fprintf(stderr, "region.protection = %s\n", prot_str);
    }

    page_restore_t page_restore = {
        .page_addr = page_boundary,
        .pagesize = pagesize,
        .data = data,
        .protection = protection,
    };
    if ((kr = restore_page(task, &page_restore)) != KERN_SUCCESS) {
        fatal_mach("restore_page", kr);
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
    setup_exception_handling(task, &exception_port);

    sync_sema = dispatch_semaphore_create(0);
    if (!sync_sema) fatal("dispatch_semaphore_create");

    pthread_t s_exc_thread;
    if (pthread_create(&s_exc_thread, NULL, exception_server_thread,
            &exception_port) != 0) {
        fatal("pthread_create");
    }

    if (dispatch_semaphore_wait(sync_sema,
                    dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) != 0) {
        fatal("timed out after 2s waiting for pthread_create");
    }

    fprintf(stderr, "Waiting for process to reach safepoint...\n");
    if ((kr = task_resume(task)) != KERN_SUCCESS) {
        fatal_mach("task_resume", kr);
    }

    if (dispatch_semaphore_wait(sync_sema,
                dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC)) != 0) {
        // This is quite likely, so we restore the written page before exiting
        if ((kr = task_suspend(task)) != 0) {
            log_mach("task_suspend", kr);
        }
        if ((kr = restore_page(task, &g_breakpoint_restore)) != 0) {
            log_mach("restore_page", kr);
        }
        fatal("timed out after 20s waiting for exception");
    }

    // TODO: uninstall exception handlers

    return 0;
}
