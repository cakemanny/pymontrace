#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>

#include <fcntl.h>
#include <dirent.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// struct user_regs_struct isn't defined properly on riscv without this
// and it gives us user_hwdebug_state
#include <linux/ptrace.h>

#include <linux/elf.h>
#include <sys/uio.h>

#include <assert.h>

#include "attacher.h"

#define NELEMS(A)   (sizeof(A) / sizeof(A[0]))

#define SAFE_POINT  "PyEval_SaveThread"

#if defined(__aarch64__)
// this is what gcc gives for __builtin_trap()
//    brk    #0x3e8
    #define DEBUG_TRAP_INSTR    ((uint32_t)0xd4207d00)
    #define user_regs_retval(uregs) ((uregs).regs[0])
#elif defined(__x86_64__)
// this is what clang gives for __builtin_debugtrap()
//    int3
    #define DEBUG_TRAP_INSTR    ((uint8_t)0xcc)
    #define user_regs_retval(uregs) ((uregs).rax)
#elif defined(__riscv)
//	ebreak
    #define DEBUG_TRAP_INSTR    ((uint32_t)0x00100073)
    // x10 == a0 == first argument and also return value
    #define user_regs_retval(uregs) ((uregs).a0)
#else
    #error "unsupported arch"
#endif


__attribute__((format(printf, 1, 0)))
static void
vlog_err(const char* fmt, va_list valist)
{
    int esaved = errno;
    fprintf(stderr, "attacher: ");
    vfprintf(stderr, fmt, valist);

    if (fmt[0] != '\0' && fmt[strlen(fmt) - 1] != '\n') {
        fprintf(stderr, ": %s\n", strerror(esaved));
    }
    errno = esaved;
}

__attribute__((format(printf, 1, 2)))
static void
log_err(const char* fmt, ...)
{
    va_list valist;
    va_start(valist, fmt);
    vlog_err(fmt, valist);
    va_end(valist);
}

// Always define debug to avoid warnings about non-use.
#ifdef NDEBUG
const int debug = 0;
#else // !NDEBUG
const int debug = 1;
#endif // NDEBUG
#define log_dbg(fmt, ...) do { \
    if (debug) { fprintf(stderr, "[debug]: " fmt "\n", ##__VA_ARGS__); } \
} while (0)

typedef struct {
    uintptr_t addr_start;
    uintptr_t addr_end;
    char perms[4];
    uintptr_t offset;
    //dev_t dev;  // we don't use so I don't plan to parse
    ino_t inode;
    char* pathname;
} proc_map_t;

#define perms_has_exec(map)  ((map).perms[2] == 'x')

// A couple examples from the man page:
//   address           perms offset  dev   inode       pathname
//   00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon
//   f2c6ff8c000-7f2c7078c000 rw-p 00000000 00:00 0    [stack:986]
static int
parse_proc_map(char* line, proc_map_t* out)
{
    char* saveptr = NULL;
    char* addr_start = strtok_r(line, "-", &saveptr);
    if (!addr_start)  return -1;
    char* endptr = NULL;
    out->addr_start = strtoul(addr_start, &endptr, 16);
    if (addr_start[0] == '\0' || endptr[0] != '\0') {
        perror("strtoul(addr_start,...)");
        return -1;
    }

    char* addr_end = strtok_r(NULL, " \t", &saveptr);
    if (!addr_end)  return -1;
    out->addr_end = strtoul(addr_end, &endptr, 16);
    if (addr_end[0] == '\0' || endptr[0] != '\0') {
        perror("strtoul(addr_end,...)");
        return -1;
    }

    char* perms = strtok_r(NULL, " \t", &saveptr);
    if (!perms) return -1;
    if (strlen(perms) < 4) { return -1; }
    memcpy(&out->perms, perms, 4);

    char* offset = strtok_r(NULL, " \t", &saveptr);
    if (!offset) return -1;
    out->offset = strtoul(offset, &endptr, 16);
    if (offset[0] == '\0' || endptr[0] != '\0') {
        perror("strtoul(offset,...)");
        return -1;
    }

    char* dev = strtok_r(NULL, " \t", &saveptr);
    if (!dev) return -1;
    // lookup `makedev` if we ever want to parse this

    char* inode = strtok_r(NULL, " \t", &saveptr);
    if (!inode) return -1;
    out->inode = strtoul(inode, &endptr, 10);
    if (inode[0] == '\0' || endptr[0] != '\0') {
        perror("strtoul(inode,...)");
        return -1;
    }

    char* pathname = strtok_r(NULL, " \t\n", &saveptr);
    // sometimes pathname is blank
    out->pathname = pathname;

    return 0;
}

/**
 * Get section header
 */
static inline Elf64_Shdr*
get_shdr(Elf64_Ehdr* ehdr, void* shdrs, int idx)
{
    int offset = idx * ehdr->e_shentsize;
    return ((void*)shdrs + offset);
}

typedef struct {
    uintptr_t section_addr; /* virtual addr the section should be loaded at */
                            /* this will have been moved due to ASLR though */
    uintptr_t sym_addr;     /* virtual addr of the symbol */
} elfsym_info_t;

static int
elf_find_symbol(
        const char* pathname, const char* symbol_to_find,
        elfsym_info_t* es_info)
{
    int err = 0;
    int fd = open(pathname, O_RDONLY);
    if (-1 == fd) {
        err = errno;
        perror("open");
        return err;
    }
    struct stat statbuf = {};
    if (fstat(fd, &statbuf) == -1) {
        perror("fstat");
        close(fd);
        return err;
    }

    void* mapped = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        int err = errno;
        perror("mmap");
        close(fd);
        return err;
    }
    if (close(fd) == -1) {
        perror("close");
        // but dont fail
    }

#define error(msg, _err) do { \
    fprintf(stderr, "%s\n", msg); \
    err = _err; \
    goto out; \
} while (0)


    Elf64_Ehdr ehdr = {};
    memcpy(&ehdr, mapped, sizeof ehdr);

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        error("Not elf file", ENOEXEC); }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        error("Not Elf64", ENOEXEC); }
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        error("Not Little Endian Elf", ENOEXEC); }
    if (ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
        error("Unknown Elf version", ENOEXEC); }
    if (ehdr.e_ident[EI_OSABI] != ELFOSABI_NONE
            && ehdr.e_ident[EI_OSABI] != ELFOSABI_LINUX) {
        error("Non SYSV no Linux OSABI", ENOEXEC); }

    // ident looks good!

    if (ehdr.e_phnum == 0) {
        error("not a mappable Elf file", EINVAL);
        return EINVAL;
    }
    if (ehdr.e_shstrndx == SHN_UNDEF) {
        error("no section names", ENOEXEC); }

    // Read section headers
    void* shdrs = mapped + ehdr.e_shoff;


    Elf64_Shdr* shstr = get_shdr(&ehdr, shdrs, ehdr.e_shstrndx);
    if (shstr->sh_type != SHT_STRTAB) {
        error("bad elf file: shstrtab not strtab!", ENOEXEC);
    }

    char* sh_strtab = mapped + shstr->sh_offset;

    int dynsym_ndx = -1;
    int symtab_idx = -1;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr* shdr = get_shdr(&ehdr, shdrs, i);
        if (false) {
            printf("[%d] %s  %d\n", i, &sh_strtab[shdr->sh_name], shdr->sh_type);
        }

        if (shdr->sh_type == SHT_DYNSYM) {
            assert(dynsym_ndx == -1);
            dynsym_ndx = i;
        }
        if (shdr->sh_type == SHT_SYMTAB) {
            assert(symtab_idx == -1);
            symtab_idx = i;
        }
    }
    if (symtab_idx) {} /* unused, we've not needed to find static symbols yet */

    Elf64_Sym target = {};

    if (dynsym_ndx != -1) {
        Elf64_Shdr* shdr = get_shdr(&ehdr, shdrs, dynsym_ndx);
        int dynstr_ndx = shdr->sh_link;
        if (dynstr_ndx == 0) {
            error("dynsym section sh_link is not present", ENOEXEC);
        }
        Elf64_Shdr* dynstr_hdr = get_shdr(&ehdr, shdrs, dynstr_ndx);
        if (dynstr_hdr->sh_type != SHT_STRTAB) {
            error("dynsym section sh_link is not strtab", ENOEXEC);
        }

        void* symtab = mapped + shdr->sh_offset;
        char* strtab = mapped + dynstr_hdr->sh_offset;

        if (shdr->sh_entsize <= 0) {
            error("sh_entsize 0 for dynsym", ENOEXEC);
        }

        Elf64_Sym* sym_ent = symtab;
        for (int i = 0; (void*)sym_ent < (symtab + shdr->sh_size);
                sym_ent = (void*)sym_ent + shdr->sh_entsize, i++) {

            char* symbol_name = &strtab[sym_ent->st_name];
            if (ELF_ST_TYPE(sym_ent->st_info) == STT_FUNC
                    && 0 == strcmp(symbol_name, symbol_to_find)) {
                if (false) {
                    printf("[%d] %s %llx\n", i, symbol_name, sym_ent->st_value);
                }

                memcpy(&target, sym_ent, sizeof target);
                break;
            }
        }
    }

    // So far we're checking .symtab as .dynsym seems to be working.
    // I think maybe symbols must be in .dynsym for c extensions to
    // be able to call into python.

    if (target.st_shndx == 0) {
        err = ESRCH;
        goto out;
    }

    Elf64_Shdr* shdr = get_shdr(&ehdr, shdrs, target.st_shndx);
    es_info->section_addr = shdr->sh_addr;
    es_info->sym_addr = target.st_value;

out:
    munmap(mapped, statbuf.st_size);
    return err;

#undef error
}


static uintptr_t
find_libc_start(pid_t pid)
{
    uintptr_t libc_addr = 0;
    char mapspath[PATH_MAX];
    snprintf(mapspath, PATH_MAX, "/proc/%d/maps", pid);

    FILE* f = fopen(mapspath, "r");
    if (!f) {
        log_err("fopen: %s", mapspath);
        return 0;
    }

    size_t len = 0;
    char* line = NULL;
    while (getline(&line, &len, f) != -1) {
        proc_map_t map;
        if (parse_proc_map(line, &map) != 0) {
            log_err("failed parsing a procmap line\n");
            continue;
        }
        // We only care about code
        if (!perms_has_exec(map) || map.pathname == NULL) {
            continue;
        }

        char* bname = basename(map.pathname);

        // consider libc.so.6 and also libc-2.31.so
        if (!(strstr(bname, "libc.so")
                    || (strcmp(bname, "libc-0") > 0
                        // ':' is the ascii character after '9'
                        && strcmp(bname, "libc-:") < 0))) {
            continue;
        }

        assert(map.offset == 0);
        // todo: check basename?
        // check for dups?
        libc_addr = map.addr_start;
        break;
    }

    fclose(f);
    return libc_addr;
}


static bool
in_other_mount_ns(pid_t pid)
{
    struct stat self_root_stat = {};
    if (stat("/proc/self/root/", &self_root_stat) == -1) {
        perror("stat(/proc/self/root/)");
        return false;
    }

    char rootpath[80];
    snprintf(rootpath, sizeof rootpath, "/proc/%d/root/", pid);
    struct stat pid_root_stat = {};
    if (stat(rootpath, &pid_root_stat) == -1) {
        log_err("stat: %s", rootpath);
        return false;
    }

    return (self_root_stat.st_ino != pid_root_stat.st_ino);
}


static uintptr_t
find_symbol(pid_t pid, const char* symbol, const char* fnsrchstr)
{
    uintptr_t symbol_addr = 0;
    bool other_mount_ns = in_other_mount_ns(pid);
    char mapspath[PATH_MAX];
    snprintf(mapspath, PATH_MAX, "/proc/%d/maps", pid);

    FILE* f = fopen(mapspath, "r");
    if (!f) {
        log_err("fopen: %s", mapspath);
        return 0;
    }

    size_t len = 0;
    char* line = NULL;
    while (getline(&line, &len, f) != -1) {
        if (fnsrchstr && !strstr(line, fnsrchstr)) {
            continue;
        }
        proc_map_t map;
        if (parse_proc_map(line, &map) != 0) {
            log_err("failed parsing a procmap line\n");
            continue;
        }
        // We only care about code
        if (!perms_has_exec(map) || map.pathname == NULL) {
            continue;
        }

        // The target may be in in another mount namespace, so we
        // make sure to search in it's namespace for it's libs
        char prefixed_path[PATH_MAX];
        if (other_mount_ns && map.pathname[0] == '/') {
            snprintf(prefixed_path, PATH_MAX, "/proc/%d/root%s", pid,
                    map.pathname);
        } else {
            strncpy(prefixed_path, map.pathname, PATH_MAX-1);
            prefixed_path[PATH_MAX-1] = '\0';
        }

        elfsym_info_t es_info = {};
        int err = elf_find_symbol(prefixed_path, symbol, &es_info);
        if (err == ESRCH) {
            continue;
        }
        if (err != 0) {
            log_err("error reading %s (%d)", prefixed_path, err);
            continue;
        }

        size_t map_size = map.addr_end - map.addr_start;
        if ((es_info.section_addr >= map.addr_start &&
                    es_info.section_addr < map.addr_end) &&
                (es_info.sym_addr >= map.addr_start &&
                 es_info.sym_addr < map.addr_end)) {
            // Seems very likely this mapping has not be ASLR'd.
            // Maybe that's how things are with exec files.

            symbol_addr = es_info.sym_addr;
        } else if (es_info.sym_addr > map.offset && (es_info.sym_addr < map.offset + map_size)) {
            // Maybe this one works in all cases?
            symbol_addr = (map.addr_start - map.offset) + es_info.sym_addr;
        } else {
            // and or DYN
            fprintf(stderr, "TODO: implement better SO handling\n");
        }
        break;
    }

    fclose(f);
    return symbol_addr;
}

static uintptr_t
find_pyfn(pid_t pid, const char* symbol)
{
    return find_symbol(pid, symbol, "python");
}


/* returns -1 on error */
static pid_t
wait_for_stop(pid_t pid, int signo, int* pwstatus)
{
    int wstatus = 0;
    if (!pwstatus) {
        pwstatus = &wstatus;
    }
    for (;;) {
        // TODO: timeout ?
        pid_t tid;
        if ((tid = waitpid(pid, pwstatus, 0)) == -1) {
            int esaved = errno;
            log_err("waitpid: %d", pid);
            errno = esaved;
            return -1;
        }
        if (pid > 0 && tid != pid) {
            fprintf(stderr, "pid > 0 && tid != pid\n");
            abort();
        }

        if (!WIFSTOPPED(*pwstatus)) {
            if (WIFEXITED(*pwstatus)) {
                log_err("target %d (tid=%d) exited with status %d\n", pid, tid,
                        WEXITSTATUS(*pwstatus));
            }
            if (WIFSIGNALED(*pwstatus)) {
                int signum = WTERMSIG(*pwstatus);
                log_err("target %d (tid=%d) killed by signal: %s (%d)\n", pid,
                        tid, strsignal(signum), signum);
            }
            if (pid == -1) {
                // We'll get ECHILD on the next waitpid if we run out of child
                // processes.
                continue;
            }
            return -1;
        }
        if (WIFSTOPPED(*pwstatus) && WSTOPSIG(*pwstatus) != signo) {
            if (ptrace(PTRACE_CONT, tid, 0, WSTOPSIG(*pwstatus)) == -1) {
                int esaved = errno;
                log_err("ptrace cont: %d", tid);
                errno = esaved;
                return -1;
            }
            continue;
        }
        return tid;
    }
}

static int
continue_sgl_thread(pid_t tid)
{
    if (ptrace(PTRACE_CONT, tid, 0, 0) == -1) {
        log_err("ptrace cont: tid=%d", tid);
        return -1;
    }
    return 0;
}

enum { MAX_THRDS = 16 };

struct tgt_thrd {
    pid_t       tid;
    int         wstatus;
    unsigned    attached    : 1,
                hw_bp_set   : 1,
                running     : 1;
};

static inline void
thrd_set_exited(struct tgt_thrd* t)
{
    t->attached = 0;
    t->hw_bp_set = 0;
    t->running = 0;
}

static int
get_threads(pid_t pid, struct tgt_thrd* thrd, int *numthrds)
{
    char pathname[80] = {};
    snprintf(pathname, sizeof pathname, "/proc/%d/task", pid);
    DIR* dir = opendir(pathname);
    if (dir == NULL) {
        log_err("opendir: %s", pathname);
        return 1;
    }

    errno = 0;
    int i = 0;
    for (struct dirent* ent; (ent = readdir(dir)) != NULL; errno = 0, i++) {
        int tid = atoi(ent->d_name);
        if (tid == 0) { --i; continue; }
        if (*numthrds == 0) {
            continue;
        }
        if (i >= *numthrds) {
            log_err("too many threads\n");
            return 1;
        }
        thrd[i].tid = tid;
    }
    if (errno != 0) {
        log_err("readdir");
        return 1;
    }
    *numthrds = i;
    return 0;
}


static int
attach_threads(struct tgt_thrd* thrds, int count)
{
    int err = 0;

    int i = 0;
    for (; i < count; i++) {
        __auto_type t = &thrds[i];
        if ((err = ptrace(PTRACE_SEIZE, t->tid, 0, 0)) == -1) {
            log_err("ptrace attach: tid=%d", t->tid);
            goto error;
        }
        t->attached = 1;
        t->running = 1;
        if ((err = ptrace(PTRACE_INTERRUPT, t->tid, 0, 0)) == -1) {
            log_err("ptrace interrupt: tid=%d", t->tid);
            goto error;
        }
        if ((err = wait_for_stop(t->tid, SIGTRAP, &t->wstatus)) == -1) {
            goto error;
        }
        t->running = 0;
    }
    return 0;

error:
    err = ATT_FAIL;
    for (; i > 0; i--) {
        if (ptrace(PTRACE_DETACH, thrds[i].tid, 0, 0) == -1) {
            log_err("ptrace detach: tid=%d", thrds[i].tid);
            err = ATT_UNKNOWN_STATE;
        }
        thrds[i].attached = 0;
    }
    return err;
}

static int
detach_threads(struct tgt_thrd* thrds, int count)
{
    int err = 0;
    for (int i = 0; i < count; i++) {
        if (!thrds[i].attached) {
            continue;
        }
        err = ptrace(PTRACE_DETACH, thrds[i].tid, 0, 0);
        if (err == -1) {
            log_err("ptrace detach: tid=%d", thrds[i].tid);
        }
        thrds[i].attached = 0;
    }
    return err;
}

static int
continue_threads(struct tgt_thrd* thrds, int count)
{
    int err = 0;
    for (int i = 0; i < count; i++) {
        err = ptrace(PTRACE_CONT, thrds[i].tid, 0, 0);
        if (err == -1) {
            log_err("ptrace cont: tid=%d", thrds[i].tid);
            err = ATT_UNKNOWN_STATE;
        }
        thrds[i].running = 1;
    }
    return err;
}

static int
interrupt_threads(struct tgt_thrd* thrds, int nthreads)
{
    int err = 0;
    for (int i = 0; i < nthreads; i++) {
        __auto_type t = &thrds[i];
        if (!t->attached) {
            continue; // should only be exited threads.
        }
        if (ptrace(PTRACE_INTERRUPT, t->tid, 0, 0) == -1) {
            if (errno == ESRCH) {
                thrd_set_exited(t);
                continue;
            } else {
                log_err("ptrace interrupt: tid=%d", t->tid);
                return ATT_UNKNOWN_STATE;
            }
        }
        if (wait_for_stop(t->tid, SIGTRAP, &t->wstatus) == -1) {
            if (WIFEXITED(t->wstatus)) {
                thrd_set_exited(t);
                continue;
            } else {
                if (WIFSIGNALED(t->wstatus)) {
                    thrd_set_exited(t);
                }
                return ATT_UNKNOWN_STATE;
            }
        }
        if ((t->wstatus >> 8) != ((PTRACE_EVENT_STOP << 8) | SIGTRAP)) {
            // TODO: this might be our breakpoint and not the event-stop.
            // If on x86, we may need to roll back the instruction pointer
            // a byte.
            log_err("not event-stop!!!\n");
            // Maybe we should just kill the target until we've addressed
            // this TODO.
            #ifdef __x86_64__
                return ATT_UNKNOWN_STATE;
            #endif
        }
    }
    return err;
}

static int
count_attached_threads(struct tgt_thrd* thrds, int nthreads)
{
    int count = 0;
    for (int i = 0; i < nthreads; i++) {
        count += thrds[i].attached;
    }
    log_dbg("%s:%d count = %d", __FILE__, __LINE__, count);
    return count;
}

static int
find_thread_idx(struct tgt_thrd* thrds, int nthreads, pid_t tid)
{
    for (int i = 0; i < nthreads; i++) {
        if (thrds[i].tid == tid) {
            return i;
        }
    }
    return -1;
}

static struct tgt_thrd*
find_thread(struct tgt_thrd* thrds, int nthreads, pid_t tid)
{
    int idx = find_thread_idx(thrds, nthreads, tid);
    if (idx == -1) {
        return NULL;
    }
    return &thrds[idx];
}

/*
 * thrds_a is a previous read of the threads in a task which already tracks
 * which threads are attached and stopped.
 * thrds_b is a new read of the threads that took place after the stopping
 * and thus may contain threads that were created during the stopping of the
 * threads in thrds_a.
 *
 * merge_threads merges the list of threads in b into a but retains the info
 * about their status
 *
 * returns 0 if the thread lists are the same non-zero otherwise.
 */
static int
merge_threads(
        struct tgt_thrd* thrds_a, int* count_a,
        struct tgt_thrd* thrds_b, int count_b)
{
    bool changed = false;
    if (*count_a != count_b) {
        changed = true;
    }

    for (int i = 0; i < count_b; i++) {
        __auto_type in_a = find_thread(thrds_a, *count_a, thrds_b[i].tid);
        if (in_a == NULL) {
            changed = true;
        } else {
            thrds_b[i] = *in_a;
        }
    }
    memcpy(thrds_a, thrds_b, count_b * sizeof *thrds_b);
    *count_a = count_b;
    return changed ? 1 : 0;
}

static int
attach_all_threads(
        pid_t pid,
        struct tgt_thrd* thrds, int* pnthreads)
{
    int err = 0;
    int nthreads = *pnthreads;

    struct tgt_thrd cmp_thrds[MAX_THRDS] = {};
    int cmp_nthreads = MAX_THRDS;

    err = get_threads(pid, thrds, &nthreads);
    if (err != 0) {
        return ATT_FAIL;
    }

    int loop_count = 0;
    do {
        if (loop_count++ > 10) {
            log_err("unable to stop all threads");
            err = ATT_FAIL;
            goto error;
        }
        err = attach_threads(thrds, nthreads);
        if (err != 0) {
            goto error;
        }

        cmp_nthreads = MAX_THRDS;
        if ((err = get_threads(pid, cmp_thrds, &cmp_nthreads)) != 0) {
            goto error;
        }

    } while (merge_threads(thrds, &nthreads, cmp_thrds, cmp_nthreads) != 0);

    *pnthreads = nthreads;
    return err;

error:
    if (detach_threads(thrds, nthreads) != 0) {
        err = ATT_UNKNOWN_STATE;
    }
    return err;
}

/*
 * ptrace pokedata takes a machine word, i.e. 64 bits. so we create
 * useful union to cast it into bytes or half-words, whatever is useful.
 */
typedef union {
    char c_bytes[8];
    uint32_t u32s[2];
    uint64_t u64;
} word_of_instr_t;

typedef struct {
    word_of_instr_t instrs;
    uintptr_t addr;
} saved_instrs_t;

static int
save_instrs(pid_t pid, saved_instrs_t* psaved)
{
    struct iovec local = {
        .iov_base = psaved->instrs.c_bytes,
        .iov_len = sizeof psaved->instrs,
    };
    struct iovec remote = {
        .iov_base = (void*)psaved->addr,
        .iov_len = sizeof psaved->instrs,
    };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0)
            != (ssize_t)remote.iov_len) {
        log_err("process_vm_readv: pid=%d", pid);
        return ATT_FAIL;
    }
    return 0;
}

static int
restore_instrs(pid_t tid, saved_instrs_t* psaved)
{
    if (-1 == ptrace(PTRACE_POKETEXT, tid, psaved->addr, psaved->instrs.u64)) {
        log_err("restore_instrs: ptrace poketext: tid=%d", tid);
        return -1;
    }
    return 0;
}

static int
replace_instrs(pid_t tid, uintptr_t addr, word_of_instr_t instrs)
{
    if (-1 == ptrace(PTRACE_POKETEXT, tid, addr, instrs.u64)) {
        log_err("replace_instrs: ptrace poketext: tid=%d", tid);
        return -1;
    }
    return 0;
}

#if defined(__aarch64__)

typedef struct {
    struct user_hwdebug_state state;
} hw_bp_ctx_t;

static int
__set_hw_breakpoint(pid_t tid, struct user_hwdebug_state* state)
{
    // It's not permitted to write back more than the available number of
    // regs. Thank you
    // https://aarzilli.github.io/debugger-bibliography/hwbreak.html
    size_t count_dbg_regs = (state->dbg_info & 0xff);
    size_t len = offsetof(struct user_hwdebug_state, dbg_regs[count_dbg_regs]);
    struct iovec iov = {
        .iov_base = state,
        .iov_len = len,
    };
    return ptrace(PTRACE_SETREGSET, tid, NT_ARM_HW_BREAK, &iov);
}

static void
hw_bp_print_ctl(uint32_t ctrl)
{
    // https://developer.arm.com/documentation/101111/0101/AArch64-Debug-registers/DBGBCRn-EL1--Debug-Breakpoint-Control-Registers--EL1
    char bits[33] = {};
    for (int i = 0; i < 32; i++) {
        bits[31-i] = '0' + !!(ctrl & (1 << i));
    }
    if (bits[32] != 0) abort();
    log_dbg("ctrl = %s", bits);
    log_dbg("       %s", "        ^~~~^~~~^~^    ^~~~  ^~^");
    log_dbg("       %s", "        BT  LBN | |    BAS   | E");
    log_dbg("       %s", "              SSC HMC       PMC ");
}

static int
set_hw_breakpoint(pid_t tid, uintptr_t bp_addr, hw_bp_ctx_t* oldctx)
{
    struct iovec iov = {
        .iov_base = &oldctx->state,
        .iov_len = sizeof oldctx->state,
    };
    if (-1 == ptrace(PTRACE_GETREGSET, tid, NT_ARM_HW_BREAK, &iov)) {
        log_err("set_hw_breakpoint: ptrace getregset: tid=%d", tid);
        return -1;
    }
    struct user_hwdebug_state hdb_regs = oldctx->state;

    int count_dbg_regs = (oldctx->state.dbg_info & 0xff);

    int reg_idx = -1;
    for (int i = 0; i < count_dbg_regs; i++) {
        if (hdb_regs.dbg_regs[i].addr == 0) {
            reg_idx = i;
        }
    }
    if (reg_idx == -1) {
        log_err("no free hardware debug registers\n");
        return -1;
    }

    hw_bp_print_ctl(hdb_regs.dbg_regs[reg_idx].ctrl);

    uint32_t ctrl = 0;
    ctrl |= (0xf << 5); /* BAS: match A64 / A32 instruction */
    ctrl |= (0b10 << 1); /* PMC: Select EL0 only */
    ctrl |= 1; /* Enable breakpoint */

    hdb_regs.dbg_regs[reg_idx].ctrl = ctrl;
    hdb_regs.dbg_regs[reg_idx].addr = bp_addr;


    if (-1 == __set_hw_breakpoint(tid, &hdb_regs)) {
        log_err("set_hw_breakpoint: ptrace setregset: tid=%d", tid);
        return -1;
    }

    return 0;
}

static int
remove_hw_breakpoint(pid_t tid, hw_bp_ctx_t* oldctx)
{
    if (-1 == __set_hw_breakpoint(tid, &oldctx->state)) {
        log_err("remove_hw_breakpoint: ptrace setregset: tid=%d", tid);
        return -1;
    }
    return 0;
}

#elif defined(__x86_64__)

typedef struct {
    int reg_idx;
    uint64_t ctrl;
} hw_bp_ctx_t;

#define CR_IDX  7   /* control register index */

static int
read_dbg_reg(pid_t tid, int regidx, uint64_t* value)
{
    long err;
    errno = 0;
    err = ptrace(PTRACE_PEEKUSER, tid,
            offsetof(struct user,u_debugreg[regidx]), 0);
    if (-1 == err && errno != 0) {
        return -1;
    }
    *value = (uint64_t)err;
    return 0;
}

static int
write_dbg_reg(pid_t tid, int regidx, uint64_t value)
{
    return ptrace(PTRACE_POKEUSER, tid,
                offsetof(struct user, u_debugreg[regidx]), value);
}

static int
set_hw_breakpoint(pid_t tid, uintptr_t bp_addr, hw_bp_ctx_t* oldctx)
{
    // Look for a free debug register in DR0-3
    // (DR4 and DR5 are reserved for the kernel)
    int dr_idx = -1;
    for (int i = 0; i < 4; i++) {
        uintptr_t drv;
        if (-1 == read_dbg_reg(tid, i, &drv)) {
            log_err("ptrace peekuser: tid=%d: dr%d", tid, i);
            return -1;
        }
        if (drv == 0) {
            dr_idx = i;
            break;
        }
    }
    if (-1 == dr_idx) {
        log_err("no free hw breakpoints: tid=%d\n", tid);
        return -1;
    }

    uint64_t ctrl = 0;
    if (-1 == read_dbg_reg(tid, CR_IDX, &ctrl)) {
        log_err("ptrace peekuser: dr7 (tid=%d)", tid);
        return -1;
    }

    oldctx->ctrl = ctrl;

    // The first four even numbered bits enable/disable a process local
    // breakpoint
    ctrl |= (1 << (2 * dr_idx));

    // R/W bits and LEN bits should all be zero for an intstruction execution
    // breakpoint.
    ctrl &= ~((0b1111 << (dr_idx * 4)) << 16);

    if (-1 == write_dbg_reg(tid, dr_idx, bp_addr)) {
        log_err("ptrace pokeuser: dr%d", dr_idx);
        return -1;
    }
    if (-1 == write_dbg_reg(tid, CR_IDX, ctrl)) {
        log_err("ptrace pokeuser: dr7");
        write_dbg_reg(tid, dr_idx, 0UL); /* unset addr */
        return -1;
    }
    return 0;
}

static int
remove_hw_breakpoint(pid_t tid, hw_bp_ctx_t* oldctx)
{
    int dr_idx = oldctx->reg_idx;

    uint64_t ctrl = 0;
    if (-1 == read_dbg_reg(tid, CR_IDX, &ctrl)) {
        log_err("ptrace peekuser: dr7 (tid=%d)", tid);
        return -1;
    }

    // Clear DR0-3 local enable bit.
    ctrl &= ~(1 << (2 * dr_idx));
    // Don't bother with restoring the settings.

    if (-1 == write_dbg_reg(tid, dr_idx, 0UL)) {
        log_err("ptrace pokeuser: dr%d (tid=%d)", dr_idx, tid);
        return -1;
    }
    if (-1 == write_dbg_reg(tid, CR_IDX, ctrl)) {
        log_err("ptrace pokeuser: dr7 (tid=%d)", tid);
        return -1;
    }
    return 0;
}

#endif // defined(__aarch64__)

static int
get_user_regs(pid_t tid, struct user_regs_struct* user_regs)
{
    struct iovec iov = {.iov_base = user_regs, .iov_len = sizeof *user_regs};
    if (-1 == ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov)) {
        int esaved = errno;
        log_err("ptrace getregset: tid=%d", tid);
        errno = esaved;
        return -1;
    }
    if (iov.iov_len != sizeof *user_regs) {
        log_err("iov.iov_len = %lu, sizeof user_regs = %lu\n",
                iov.iov_len, sizeof user_regs);
    }
    return 0;
}

static int
set_user_regs(pid_t tid, struct user_regs_struct* user_regs)
{
    struct iovec iov = {.iov_base = user_regs, .iov_len = sizeof *user_regs};
    if (-1 == ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov)) {
        int esaved = errno;
        log_err("ptrace setregset: tid=%d", tid);
        errno = esaved;
        return -1;
    }
    return 0;
}


#ifndef __x86_64__
__attribute__((unused))
#endif
static int
set_pc(pid_t tid, uintptr_t pc, uintptr_t* oldpc)
{
    struct user_regs_struct user_regs = {};
    if (-1 == get_user_regs(tid, &user_regs)) {
        return -1;
    }
#if defined(__aarch64__) || defined(__riscv)
    if (oldpc) {
        *oldpc = user_regs.pc;
    }
    user_regs.pc = pc;
#elif defined(__x86_64__)
    if (oldpc) {
        *oldpc = user_regs.rip;
    }
    user_regs.rip = pc;
#endif
    if (-1 == set_user_regs(tid, &user_regs)) {
        return -1;
    }
    return 0;
}

static void
prepare_syscall6(
        struct user_regs_struct* user_regs, long pc, long num,
        long arg1, long arg2, long arg3, long arg4, long arg5, long arg6)
{
#if defined(__aarch64__)
    user_regs->pc = pc;
    user_regs->regs[8] = num;
    user_regs->regs[0] = arg1;
    user_regs->regs[1] = arg2;
    user_regs->regs[2] = arg3;
    user_regs->regs[3] = arg4;
    user_regs->regs[4] = arg5;
    user_regs->regs[5] = arg6;
#elif defined(__x86_64__)
    user_regs->rax = num;
    user_regs->rdi = arg1;
    user_regs->rsi = arg2;
    user_regs->rdx = arg3;
    user_regs->r10 = arg4;
    user_regs->r8  = arg5;
    user_regs->r9  = arg6;
    user_regs->rip = pc;
#elif defined(__riscv) && __riscv_xlen == 64
    user_regs->a7 = num;
    user_regs->a0 = arg1;
    user_regs->a1 = arg2;
    user_regs->a2 = arg3;
    user_regs->a3 = arg4;
    user_regs->a4 = arg5;
    user_regs->a5 = arg6;
    user_regs->pc = pc;
#endif
}

static void
prepare_syscall2(struct user_regs_struct* user_regs, long pc, long num,
        long arg1, long arg2)
{
    prepare_syscall6(user_regs, pc, num, arg1, arg2, 0, 0, 0, 0);
}

static word_of_instr_t
syscall_and_brk()
{
    word_of_instr_t retval = {
        #if defined(__aarch64__)
            .u32s[0] = 0xd4000001, /* svc	#0 */
            .u32s[1] = DEBUG_TRAP_INSTR,
        #elif defined(__x86_64__)
            .c_bytes[0] = 0x0f, .c_bytes[1] = 0x05, /* syscall */
            .c_bytes[2] = DEBUG_TRAP_INSTR,
        #elif defined(__riscv) && __riscv_xlen == 64
            // We use the 32-bit instructions so that we don't need to check
            // whether the processor supports the RVC extension.
            .u32s[0] = 0x00000073, /* ecall */
            .u32s[1] = DEBUG_TRAP_INSTR,
        #endif
    };
    return retval;
}

static int
call_mmap_in_target(pid_t pid, pid_t tid, uintptr_t bp_addr, size_t length,
        uintptr_t* addr)
{
    int err = 0;

    // If we run into bugs with FP registers we may want to expand this
    // to also save and restore FP regs
    // Also, maybe this should be elf_gregset_t ... not sure
    struct user_regs_struct user_regs = {};
    if (-1 == get_user_regs(tid, &user_regs)) {
        return ATT_FAIL;
    }

    saved_instrs_t saved_instrs = { .addr = bp_addr };
    if (save_instrs(pid, &saved_instrs) != 0) {
        return ATT_FAIL;
    }

    if (-1 == replace_instrs(tid, bp_addr, syscall_and_brk())) {
        return ATT_FAIL;
    }

    // Setup registers for mmap call
    struct user_regs_struct urmmap = user_regs;

    prepare_syscall6(&urmmap, bp_addr, SYS_mmap,
            0, /* addr */
            length, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1, /* fd */
            0); /* offset */

    if (-1 == set_user_regs(tid, &urmmap)) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    if (-1 == continue_sgl_thread(tid)) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    if (wait_for_stop(tid, SIGTRAP, NULL) == -1) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    if (-1 == get_user_regs(tid, &urmmap)) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    // from linux/tools/include/nolibc/sys.h
    void* ret = (void*) user_regs_retval(urmmap);
    if ((unsigned long)ret >= -4095UL) {
        errno = -(long)ret;
        perror("mmap in target");
        err = ATT_FAIL;
    }

    *addr = (uintptr_t)ret;


restore_instructions:

    if (-1 == restore_instrs(tid, &saved_instrs)) {
        err = ATT_UNKNOWN_STATE;
        // Intentionally not going to return, in order to restore registers
    }

    if (-1 == set_user_regs(tid, &user_regs)) {
        return ATT_UNKNOWN_STATE;
    }
    return err;
}

static int
call_munmap_in_target(pid_t pid, pid_t tid, uintptr_t scratch_addr,
        uintptr_t addr, size_t length)
{
    int err = 0;

    struct user_regs_struct user_regs = {};
    if (-1 == get_user_regs(tid, &user_regs)) {
        return ATT_FAIL;
    }

    saved_instrs_t saved_instrs = { .addr = scratch_addr };
    if (save_instrs(pid, &saved_instrs) != 0) {
        return ATT_FAIL;
    }

    if (-1 == replace_instrs(tid, scratch_addr, syscall_and_brk())) {
        return ATT_FAIL;
    }

    // Setup registers for munmap call
    struct user_regs_struct call_regs = user_regs;

    prepare_syscall2(&call_regs, scratch_addr, SYS_munmap,
            addr, length);

    if (-1 == set_user_regs(tid, &call_regs)) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    if (-1 == continue_sgl_thread(tid)) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    if (wait_for_stop(tid, SIGTRAP, NULL) == -1) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    if (-1 == get_user_regs(tid, &call_regs)) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    long ret = (long)user_regs_retval(call_regs);
    if (ret < 0) {
        errno = -(long)ret;
        perror("munmap in target");
        err = ATT_FAIL;
    }

restore_instructions:
    if (-1 == restore_instrs(tid, &saved_instrs)) {
        err = ATT_UNKNOWN_STATE;
        // intentionally fall-through to restore registers
    }

    if (-1 == set_user_regs(tid, &user_regs)) {
        return ATT_UNKNOWN_STATE;
    }
    return err;
}

static ssize_t
indirect_call_and_brk2(
        pid_t pid, pid_t tid, uintptr_t scratch_addr, uintptr_t fn_addr,
        uintptr_t arg1, uintptr_t arg2, uintptr_t* retval)
{
    int err = 0;

    // If we run into bugs with FP registers we may want to expand this
    // to also save and restore FP regs
    // Also, maybe this should be elf_gregset_t ... not sure
    struct user_regs_struct user_regs = {};
    if (-1 == get_user_regs(tid, &user_regs)) {
        return ATT_FAIL;
    }

    saved_instrs_t saved_instrs = { .addr = scratch_addr };
    if (save_instrs(pid, &saved_instrs) != 0) {
        return ATT_FAIL;
    }

    word_of_instr_t indirect_call_and_brk = {
        #if defined(__aarch64__)
            .u32s[0] = 0xd63f0200,  /* blr	x16 */
            .u32s[1] = DEBUG_TRAP_INSTR,
        #elif defined(__x86_64__)
            .c_bytes[0] = 0xff, .c_bytes[1] = 0xd0, /* callq *%rax */
            .c_bytes[2] = DEBUG_TRAP_INSTR,
        #elif defined(__riscv)
            .u32s[0] = 0x000780e7, /* jalr	a5 */
            .u32s[1] = DEBUG_TRAP_INSTR,
        #endif
    };
    if (-1 == replace_instrs(tid, scratch_addr, indirect_call_and_brk)) {
        return ATT_FAIL;
    }

    // Setup registers for call
    struct user_regs_struct urcall = user_regs;

#if defined(__aarch64__)
    urcall.regs[0] = arg1;
    urcall.regs[1] = arg2;
    urcall.regs[16] = fn_addr;
    urcall.pc = scratch_addr;
#elif defined(__x86_64__)
    urcall.rdi = arg1;
    urcall.rsi = arg2;
    urcall.rax = fn_addr;
    urcall.rip = scratch_addr;
    urcall.rsp &= -16LL; // 16-byte align stack, required for xmm0 reg use
#elif defined(__riscv)
    urcall.a0 = arg1;
    urcall.a1 = arg2;
    urcall.a5 = fn_addr;
    urcall.pc = scratch_addr;
#endif

    if (-1 == set_user_regs(tid, &urcall)) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    if (-1 == continue_sgl_thread(tid)) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    if (wait_for_stop(tid, SIGTRAP, NULL) == -1) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    if (-1 == get_user_regs(tid, &urcall)) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instructions;
    }

    *retval = user_regs_retval(urcall);

restore_instructions:
    if (-1 == restore_instrs(tid, &saved_instrs)) {
        err = ATT_UNKNOWN_STATE;
        // Intentionally not going to return, in order to restore registers
    }

    if (-1 == set_user_regs(tid, &user_regs)) {
        return ATT_UNKNOWN_STATE;
    }
    return err;
}


static ssize_t
call_pyrun_simplestring(
        pid_t pid, pid_t tid, uintptr_t scratch_addr, uintptr_t buf)
{
    uint64_t PyRun_SimpleString = find_pyfn(pid, "PyRun_SimpleString");
    if (PyRun_SimpleString == 0) {
        log_err("unable to find %s\n", "PyRun_SimpleString");
        return ATT_FAIL;
    }

    uintptr_t retval = 0;
    int err = indirect_call_and_brk2(pid, tid, scratch_addr,
            PyRun_SimpleString, buf, 0, &retval);
    if (retval != 0 && err == 0) {
        log_err("PyRun_SimpleString returned an error\n");
        err = ATT_FAIL;
    }
    return err;
}


static int
exec_python_code(pid_t pid, pid_t tid, const char* python_code)
{
    int err;
    // There is a build-id at the start of glibc that we can overwrite
    // temporarily (idea from the readme of kubo/injector)
    uintptr_t libc_start_addr = find_libc_start(pid);
    if (libc_start_addr == 0) {
        log_err("could not find libc\n");
        return ATT_FAIL;
    }
    log_dbg("libc_start_addr = %lx", libc_start_addr);


    // This is the point at which we can start to do our work.
    uintptr_t mapped_addr = 0;
    size_t length = sysconf(_SC_PAGESIZE);
    if ((err = call_mmap_in_target(pid, tid, libc_start_addr, length,
                    &mapped_addr)) != 0) {
        log_err("call_mmap_in_target failed");
        return err;
    }

    ssize_t len = (1 + strlen(python_code));
    // safe to cast away const here as process_vm_writev doesn't modify
    // the local memory.
    struct iovec local = { .iov_base = (char*)python_code, .iov_len=len };
    struct iovec remote = { .iov_base = (void*)mapped_addr, .iov_len=len };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) != len) {
        perror("process_vm_writev");
        err = ATT_FAIL;
        goto out;
    }

    if ((err = call_pyrun_simplestring(pid, tid, libc_start_addr, mapped_addr))
            != 0) {
        goto out;
    }

out:
    if (call_munmap_in_target(pid, tid, libc_start_addr, mapped_addr, length)
            != 0) {
        // This is non-fatal.
    }
    return err;
}

// we should not do this, it's re-entrant ...
static volatile sig_atomic_t g_got_signal;
static void
signal_handler(/*int signo*/)
{
    g_got_signal = 1;
}

const int handled_signums[4] = {
    SIGHUP,
    SIGINT,
    SIGTERM,
    SIGQUIT
};
typedef struct {
    struct sigaction ss_act[4];
} saved_sigaction_t;

static void
install_signal_handler(saved_sigaction_t* oldactions)
{
    g_got_signal = 0; // reset global flag

    struct sigaction new_sigaction = { .sa_handler = &signal_handler, };

    const int num_signals = NELEMS(handled_signums);
    for (int i = 0; i < num_signals; i++) {
        int signo = handled_signums[i];
        if (-1 == sigaction(signo, &new_sigaction, &oldactions->ss_act[i])) {
            log_err("sigaction");
            abort(); // All sigaction errors are programming errors
        }
    }
}

static void
remove_signal_handler(saved_sigaction_t* oldactions)
{
    const int num_signals = NELEMS(handled_signums);

    for (int i = 0; i < num_signals; i++) {
        int signo = handled_signums[i];
        if (-1 == sigaction(signo, &oldactions->ss_act[i], NULL)) {
            log_err("sigaction");
            abort();
        }
    }
}

int
attach_and_execute(const int pid, const char* python_code)
{
    int err = 0;

    // TODO: check python_code size < page size

    uintptr_t breakpoint_addr = find_pyfn(pid, SAFE_POINT);
    if (breakpoint_addr == 0) {
        log_err("unable to find %s\n", SAFE_POINT);
        return ATT_FAIL;
    }
    log_dbg(SAFE_POINT " = %lx", breakpoint_addr);


    saved_sigaction_t saved_sigactions = {};
    install_signal_handler(&saved_sigactions);

    struct tgt_thrd thrds[MAX_THRDS] = {};
    int nthreads = MAX_THRDS;
    err = attach_all_threads(pid, thrds, &nthreads);
    if (err != 0) {
        goto detach;
    }

    // TODO: here, set options to trace clones, and maybe forks. (but maybe
    // not vforks).

    saved_instrs_t saved_instrs = { .addr = breakpoint_addr };
    if (save_instrs(pid, &saved_instrs) != 0) {
        err = ATT_FAIL;
        goto detach;
    }

    // Note aarch64 has 64-bit words but 32-bit instructions so
    // we only write to the first four bytes.
    word_of_instr_t breakpoint_instrs = saved_instrs.instrs;
    #if defined(__aarch64__) || defined(__riscv)
        breakpoint_instrs.u32s[0] = DEBUG_TRAP_INSTR;
    #elif defined(__x86_64__)
        breakpoint_instrs.c_bytes[0] = DEBUG_TRAP_INSTR;
    #endif
    if (-1 == replace_instrs(pid, breakpoint_addr, breakpoint_instrs)) {
        err = ATT_FAIL;
        goto detach;
    }

    fprintf(stderr, "Waiting for process to reach safepoint...\n");

    // Our safe point is within the GIL, so we're somewhat safe that
    // only one thread will hit the BP. (unless there are multiple
    // interpreters or they've disabled the GIL).

    if ((err = continue_threads(thrds, nthreads)) != 0) {
        err = ATT_UNKNOWN_STATE;
        goto detach;
    }

    pid_t tid;
    if ((tid = wait_for_stop(-1, SIGTRAP, NULL)) == -1) {
        // If this gets interrupted (EINTR), it means the user is impatient.
        // We would be better to remove the trap instruction before leaving.
        fprintf(stderr, "Cancelling...\n");

        if ((err = interrupt_threads(thrds, nthreads)) != 0) {
            goto detach;
        }

        // Check if target no longer exists. In reality this could be for
        // both expected and unexpected reasons.
        if (kill(pid, 0) == -1 && errno == ESRCH) {
            err = ATT_INTERRUPTED;
            goto detach;
        }

        if (-1 == restore_instrs(pid, &saved_instrs)) {
            err = ATT_UNKNOWN_STATE;
            goto detach;
        }
        log_err("cancelled.\n");
        err = ATT_INTERRUPTED;
        goto detach;
    }
    log_dbg("have a target thread at breakpoint: tid=%d", tid);

    for (int i = 0; i < nthreads; i++) {
        if (thrds[i].tid == tid) {
            thrds[i].running = 0;
        }
    }

    // TODO: we should check the PC that it's at (or just after) the
    // breakpoint.

    // Restore patched code
    if (-1 == restore_instrs(tid, &saved_instrs)) {
        err = ATT_UNKNOWN_STATE;
        goto detach;
    }

    // Back the instruction pointer back to the breakpoint_addr for
    // architectures where the instruction pointer still increments on the
    // trap. Note: an illegal instruction, ud2, would not have this problem
    // but then we'd have to adapt our signal handling code ... Let's compare
    // HW breakpoints before deciding.
#if defined(__x86_64__)
    if (-1 == set_pc(tid, breakpoint_addr, NULL)) {
        err = ATT_UNKNOWN_STATE; /* until we succeed with the next the
                                    instruction pointer, we're in a bad
                                    state */
        goto detach;
    }
#endif // defined(__x86_64__)

    if ((err = exec_python_code(pid, tid, python_code)) != 0) {
        // ... actually it's verbose enough
    }

    // stop the running threads so that they can be detached
    for (int i = 0; i < nthreads; i++) {
        __auto_type t = &thrds[i];
        if (!t->attached || !t->running) {
            // thread may have exited or it's the one one we exec'd code in
            continue;
        }
        int err2 = interrupt_threads(t, 1);
        if (err2 != 0) {
            err = err2;
            continue;
        }
        t->running = 0;
    }

detach:
    remove_signal_handler(&saved_sigactions);

    if (detach_threads(thrds, nthreads) != 0) {
        err = ATT_UNKNOWN_STATE;
    }
    return err;
}

int
execute_in_threads(
        int pid, uint64_t* tids, int count_tids, const char* python_code)
{
#if defined(__aarch64__) || defined(__x86_64__)
    int err = 0;
    struct tgt_thrd thrds[MAX_THRDS] = {};

    if (count_tids > MAX_THRDS) {
        log_err("too many tids\n");
        return ATT_FAIL;
    }

    for (int i = 0; i < count_tids; i++) {
        thrds[i].tid = (pid_t)tids[i];
    }
    uintptr_t breakpoint_addr = find_pyfn(pid, SAFE_POINT);
    if (breakpoint_addr == 0) {
        log_err("unable to find %s\n", SAFE_POINT);
        return ATT_FAIL;
    }

    // TODO: maybe we need to tolerate not all threads still being there.
    if ((err = attach_threads(thrds, count_tids)) != 0) {
        return err;
    }
    log_dbg("attached to %d threads", count_tids);

    hw_bp_ctx_t saved_dbg_state[MAX_THRDS] = {};
    for (int i = 0; i < count_tids; i++) {
        __auto_type t = &thrds[i];
        if (set_hw_breakpoint(t->tid, breakpoint_addr,
                    &saved_dbg_state[i]) != 0) {
            err = ATT_UNKNOWN_STATE;
            goto out;
        }
        t->hw_bp_set = 1;
    }

    if ((err = continue_threads(thrds, count_tids)) != 0) {
        goto out;
    }

    /* We can't use wait_for_stop here because we should tolerate threads
       exiting I think. */
    /* Actually we could use wait_for_stop, if it doesn't print anything */
    while (count_attached_threads(thrds, count_tids) > 0) {
        int status;
        errno = 0;
        log_dbg("waiting for bp hit");
        pid_t tid = (tid = waitpid(-1, &status, 0));
        if (-1 == tid && errno != EINTR) {
            log_err("waitpid");
            err = ATT_UNKNOWN_STATE;
            goto out;
        }
        if (errno == EINTR) {
            log_dbg("interrupted: %s", strerror(errno));
            // set ATT_INTERRUPTED ?
            goto out;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            __auto_type t = find_thread(thrds, count_tids, tid);
            if (t == NULL) {
                log_err("unknown child: tid=%d\n", tid);
                continue;
            }
            log_dbg("thread died/exited: tid=%d", t->tid);
            t->attached = 0;
            t->running = 0;
            continue;
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
            if (-1 == ptrace(PTRACE_CONT, tid, 0, WSTOPSIG(status))) {
                log_err("ptrace cont: %d", tid);
                err = ATT_UNKNOWN_STATE;
                goto out;
            }
        }
        if (!WIFSTOPPED(status)) {
            log_err("unexpected child status: %x\n", status);
            continue;
        }
        __auto_type t = find_thread(thrds, count_tids, tid);
        if (t == NULL) {
            log_err("unknown child: tid=%d\n", tid);
            ptrace(PTRACE_CONT, tid, 0, WSTOPSIG(status));
            continue;
        }
        t->running = 0;

        // TODO: we should verify that it was our breakpoint that caused the
        // trap... (on x86 this mean checking and resetting DR6).

        int tidx = find_thread_idx(thrds, count_tids, tid);

        if (-1 == remove_hw_breakpoint(tid, &saved_dbg_state[tidx])) {
            err = ATT_UNKNOWN_STATE;
            goto out;
        }
        t->hw_bp_set = 0;

        err = exec_python_code(pid, tid, python_code);
        if (err != 0) {
            log_err("failed to install probes in thread: %d\n", tid);
        }
        log_dbg("executed python code (tid=%d)", tid);

        if (-1 == detach_threads(&thrds[tidx], 1)) {
            err = ATT_UNKNOWN_STATE;
            goto out;
        }
        t->attached = 0;
        log_dbg("detached (tid=%d)", tid);
    }

out:

    for (int i = 0; i < count_tids; i++) {
        __auto_type t = &thrds[i];
        if (!t->attached) {
            continue;
        }
        if (t->running) {
            int err2 = interrupt_threads(t, 1);
            if (err2 != 0) {
                err = err2;
                continue;
            }
            t->running = 0;
        }
        if (t->hw_bp_set) {
            if (-1 == remove_hw_breakpoint(t->tid, &saved_dbg_state[i])) {
                err = ATT_UNKNOWN_STATE;
            } else {
                t->hw_bp_set = 0;
            }
        }
        if (-1 == detach_threads(&thrds[i], 1)) {
            err = ATT_UNKNOWN_STATE;
            continue;
        }
        t->attached = 0;
    }

    return err;
#else /* !__aarch64__ */

    if (pid) {}; /* unused */
    if (tids) {}; /* unused */
    if (count_tids) {}; /* unused */
    if (python_code) {}; /* unused */

    return -1; /* not implemented */
#endif /* __aarch64__ */
}
