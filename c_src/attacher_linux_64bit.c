#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#if defined(__riscv) && __riscv_xlen == 64
    // struct user_regs_struct isn't defined properly without this
    #include <linux/ptrace.h>
#endif
#include <linux/elf.h>
#include <sys/uio.h>

#include <assert.h>

#include "attacher.h"

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


#define log_err(fmt, ...) fprintf(stderr, "attacher: " fmt "\n", ##__VA_ARGS__)

// Always define debug to avoid warnings about non-use.
#ifdef NDEBUG
const int debug = 0;
#else
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
        log_err("fopen: %s: %s", mapspath, strerror(errno));
        return 0;
    }

    size_t len = 0;
    char* line = NULL;
    while (getline(&line, &len, f) != -1) {
        proc_map_t map;
        if (parse_proc_map(line, &map) != 0) {
            log_err("failed parsing a procmap line");
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
        log_err("stat: %s: %s", rootpath, strerror(errno));
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
        log_err("fopen: %s: %s", mapspath, strerror(errno));
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
            log_err("failed parsing a procmap line");
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
            log_err("waitpid: %d: %s", pid, strerror(errno));
            errno = esaved;
            return -1;
        }

        if (!WIFSTOPPED(*pwstatus)) {
            fprintf(stderr, "WIFEXITED(wstatus)=%d, WIFSIGNALED(wstatus)=%d\n",
                    WIFEXITED(*pwstatus), WIFSIGNALED(*pwstatus));
            return -1;
        }
        if (WIFSTOPPED(*pwstatus) && WSTOPSIG(*pwstatus) != signo) {
            if (ptrace(PTRACE_CONT, tid, 0, WSTOPSIG(*pwstatus)) == -1) {
                int esaved = errno;
                log_err("ptrace cont: %d: %s", tid, strerror(errno));
                errno = esaved;
                return -1;
            }
            continue;
        }
        return tid;
    }
}

struct tgt_thrd {
    pid_t tid;
    int wstatus;
};

static int
get_threads(pid_t pid, struct tgt_thrd* thrd, int *numthrds)
{
    char pathname[80] = {};
    snprintf(pathname, sizeof pathname, "/proc/%d/task", pid);
    DIR* dir = opendir(pathname);

    errno = 0;
    int i = 0;
    for (struct dirent* ent; (ent = readdir(dir)) != NULL; errno = 0, i++) {
        int tid = atoi(ent->d_name);
        if (tid == 0) { --i; continue; }
        if (*numthrds == 0) {
            continue;
        }
        if (i >= *numthrds) {
            log_err("too many threads");
            return 1;
        }
        thrd[i].tid = tid;
    }
    if (errno != 0) {
        log_err("readdir: %s: ", strerror(errno));
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
            log_err("ptrace attach: tid=%d: %s", t->tid, strerror(errno));
            goto error;
        }
        if ((err = ptrace(PTRACE_INTERRUPT, t->tid, 0, 0)) == -1) {
            log_err("ptrace interrupt: tid=%d: %s", t->tid, strerror(errno));
            goto error;
        }

        if ((err = wait_for_stop(t->tid, SIGTRAP, &t->wstatus)) == -1) {
            goto error;
        }
    }
    return 0;

error:
    err = ATT_FAIL;
    for (; i > 0; i--) {
        if (ptrace(PTRACE_DETACH, thrds[i].tid, 0, 0) == -1) {
            log_err("ptrace detach: tid=%d: %s", thrds[i].tid,
                    strerror(errno));
            err = ATT_UNKNOWN_STATE;
        }
    }
    return err;
}

static int
detach_threads(struct tgt_thrd* thrds, int count)
{
    int err = 0;
    for (int i = 0; i < count; i++) {
        err = ptrace(PTRACE_DETACH, thrds[i].tid, 0, 0);
        if (err == -1) {
            fprintf(stderr, "ptrace detach: tid=%d: %s\n", thrds[i].tid,
                    strerror(errno));
        }
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
            fprintf(stderr, "ptrace cont: tid=%d: %s\n", thrds[i].tid,
                    strerror(errno));
            err = ATT_UNKNOWN_STATE;
        }
    }
    return err;
}

static int
interrupt_threads(struct tgt_thrd* thrds, int nthreads)
{
    int err = 0;
    for (int i = 0; i < nthreads; i++) {
        __auto_type t = &thrds[i];
        if (ptrace(PTRACE_INTERRUPT, t->tid, 0, 0) == -1) {
            log_err("ptrace interrupt: tid=%d: %s", t->tid, strerror(errno));
            return ATT_UNKNOWN_STATE;
        }
        if (wait_for_stop(t->tid, SIGTRAP, &t->wstatus) == -1) {
            return ATT_UNKNOWN_STATE;
        }
        if ((t->wstatus >> 8) != ((PTRACE_EVENT_STOP << 8) | SIGTRAP)) {
            // TODO: this might be our breakpoint and not the event-stop.
            // If on x86, we may need to roll back the instruction pointer
            // a byte.
            log_err("not event-stop!!!");
            // Maybe we should just kill the target until we've addressed
            // this TODO.
            #ifdef __x86_64__
                return ATT_UNKNOWN_STATE
            #endif
        }
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


static int
save_instrs(pid_t pid, word_of_instr_t* psaved, uintptr_t addr)
{
    struct iovec local = {
        .iov_base = psaved->c_bytes,
        .iov_len = sizeof *psaved,
    };
    struct iovec remote = {
        .iov_base = (void*)addr,
        .iov_len = sizeof *psaved,
    };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0)
            != (ssize_t)remote.iov_len) {
        log_err("process_vm_readv: pid=%d: %s", pid, strerror(errno));
        return ATT_FAIL;
    }
    return 0;
}

static int
set_pc(pid_t tid, uintptr_t pc, uintptr_t* oldpc)
{
    struct user_regs_struct user_regs = {};
    struct iovec iov = {.iov_base = &user_regs, .iov_len = sizeof user_regs};
    if (-1 == ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov)) {
        perror("ptrace(PTRACE_GETREGSET,...)");
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
    if (-1 == ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov)) {
        perror("ptrace(PTRACE_SETREGSET,...)");
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
    urmmap->rax = num;
    urmmap->rdi = arg1;
    urmmap->rsi = arg2;
    urmmap->rdx = arg3;
    urmmap->r10 = arg4;
    urmmap->r8  = arg5;
    urmmap->r9  = arg6;
    urmmap->rip = pc;
#elif defined(__riscv) && __riscv_xlen == 64
    urmmap->a7 = num;
    urmmap->a0 = arg1;
    urmmap->a1 = arg2;
    urmmap->a2 = arg3;
    urmmap->a3 = arg4;
    urmmap->a4 = arg5;
    urmmap->a5 = arg6;
    urmmap->pc = pc;
#endif
}


static int
call_mmap_in_target(pid_t pid, pid_t tid, uintptr_t bp_addr, uintptr_t* addr)
{
    int err = 0;

    // If we run into bugs with FP registers we may want to expand this
    // to also save and restore FP regs
    // Also, maybe this should be elf_gregset_t ... not sure
    struct user_regs_struct user_regs = {};
    struct iovec iov = {.iov_base = &user_regs, .iov_len = sizeof user_regs};

    if (-1 == ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov)) {
        perror("ptrace(PTRACE_GETREGSET,...)");
        return ATT_FAIL;
    }
    if (iov.iov_len != sizeof user_regs) {
        fprintf(stderr, "iov.iov_len = %lu, sizeof user_regs = %lu\n",
                iov.iov_len, sizeof user_regs);
    }

    word_of_instr_t saved_instrs = {};
    if (save_instrs(pid, &saved_instrs, bp_addr) != 0) {
        return ATT_FAIL;
    }

    word_of_instr_t syscall_and_brk = {
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

    if (-1 == ptrace(PTRACE_POKETEXT, tid, (void*)bp_addr,
                syscall_and_brk.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        return ATT_FAIL;
    }

    // Setup registers for mmap call
    struct user_regs_struct urmmap = user_regs;

    prepare_syscall6(&urmmap, bp_addr, SYS_mmap,
            0, /* addr */
            sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1, /* fd */
            0); /* offset */


    struct iovec iov_mmap = {.iov_base = &urmmap, .iov_len = sizeof urmmap};

    if (-1 == ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov_mmap)) {
        perror("ptrace(PTRACE_SETREGSET, ...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }

    if (ptrace(PTRACE_CONT, tid, 0, 0) == -1) {
        perror("ptrace(PTRACE_CONT, ...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }

    int stopped_tid = -1;
    if ((stopped_tid = wait_for_stop(tid, SIGTRAP, NULL)) == -1) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }
    if (stopped_tid != tid) { abort(); }

    if (-1 == ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov_mmap)) {
        perror("ptrace(PTRACE_GETREGSET, ...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }

    // from linux/tools/include/nolibc/sys.h
    void* ret = (void*) user_regs_retval(urmmap);
    if ((unsigned long)ret >= -4095UL) {
        errno = -(long)ret;
        perror("mmap in target");
        err = ATT_FAIL;
    }

    *addr = (uintptr_t)ret;


restore_instuctions:

    if (-1 == ptrace(PTRACE_POKETEXT, tid, (void*)bp_addr,
                saved_instrs.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        err = ATT_UNKNOWN_STATE;
        // Intentionally not going to return, in order to restore registers
    }

    if (-1 == ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov)) {
        perror("ptrace(PTRACE_SETREGSET,...)");
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
    struct iovec iov = {.iov_base = &user_regs, .iov_len = sizeof user_regs};

    if (-1 == ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov)) {
        perror("ptrace(PTRACE_GETREGSET,...)");
        return ATT_FAIL;
    }
    if (iov.iov_len != sizeof user_regs) {
        fprintf(stderr, "iov.iov_len = %lu, sizeof user_regs = %lu\n",
                iov.iov_len, sizeof user_regs);
    }

    word_of_instr_t saved_instrs = {};
    if (save_instrs(pid, &saved_instrs, scratch_addr) != 0) {
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
    if (-1 == ptrace(PTRACE_POKETEXT, tid, (void*)scratch_addr,
                indirect_call_and_brk.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
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
#elif defined(__riscv)
    urcall.a0 = arg1;
    urcall.a1 = arg2;
    urcall.a5 = fn_addr;
    urcall.pc = scratch_addr;
#endif

    struct iovec iov_call = {.iov_base = &urcall, .iov_len = sizeof urcall};

    if (-1 == ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov_call)) {
        perror("ptrace(PTRACE_SETREGSET,...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }

    if (ptrace(PTRACE_CONT, tid, 0, 0) == -1) {
        perror("ptrace(PTRACE_CONT, ...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }

    int stopped_tid = -1;
    if ((stopped_tid = wait_for_stop(tid, SIGTRAP, NULL)) == -1) {
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }
    if (stopped_tid != tid) { abort(); }

    if (-1 == ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov_call)) {
        perror("ptrace(PTRACE_GETREGSET,...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }

    *retval = user_regs_retval(urcall);

restore_instuctions:
    if (-1 == ptrace(PTRACE_POKETEXT, tid, (void*)scratch_addr,
                saved_instrs.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        err = ATT_UNKNOWN_STATE;
        // Intentionally not going to return, in order to restore registers
    }

    if (-1 == ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov)) {
        perror("ptrace(PTRACE_SETREGSET,...)");
        return ATT_UNKNOWN_STATE;
    }

    return err;
}


static ssize_t
add_pending_in_target(
        pid_t pid, pid_t tid, uintptr_t scratch_addr, uintptr_t fn_addr,
        uintptr_t arg)
{
    uintptr_t add_pending_call_addr = find_pyfn(pid, "Py_AddPendingCall");

    if (add_pending_call_addr == 0) {
        log_err("failed to find symbol Py_AddPendingCall");
        return ATT_FAIL;
    }

    uintptr_t retval = 0;
    int err = indirect_call_and_brk2(pid, tid, scratch_addr,
            add_pending_call_addr, fn_addr, arg, &retval);
    if (retval != 0 && err == 0) {
        log_err("Py_AddPendingCall returned an error");
        err = ATT_FAIL;
    }
    return err;
}

static ssize_t
call_pyrun_simplestring(
        pid_t pid, pid_t tid, uintptr_t scratch_addr, uintptr_t buf)
{
    uint64_t PyRun_SimpleString = find_pyfn(pid, "PyRun_SimpleString");
    if (PyRun_SimpleString == 0) {
        fprintf(stderr, "unable to find %s\n", "PyRun_SimpleString");
        return ATT_FAIL;
    }

    uintptr_t retval = 0;
    int err = indirect_call_and_brk2(pid, tid, scratch_addr,
            PyRun_SimpleString, buf, 0, &retval);
    if (retval != 0 && err == 0) {
        log_err("PyRun_SimpleString returned an error");
        err = ATT_FAIL;
    }
    return err;
}


static int
exec_python_code(pid_t pid, pid_t tid, const char* python_code, pid_t* mtid)
{
    int err;
    // There is a build-id at the start of glibc that we can overwrite
    // temporarily (idea from the readme of kubo/injector)
    uintptr_t libc_start_addr = find_libc_start(pid);
    if (libc_start_addr == 0) {
        fprintf(stderr, "could not find libc\n");
        return ATT_FAIL;
    }
    log_dbg("libc_start_addr = %lx\n", libc_start_addr);


    // This is the point at which we can start to do our work.
    uintptr_t mapped_addr = 0;
    if ((err = call_mmap_in_target(pid, tid, libc_start_addr, &mapped_addr)) != 0) {
        fprintf(stderr, "call_mmap_in_target failed\n");
        return err;
    }

    ssize_t len = (1 + strlen(python_code));
    // safe to cast away const here as process_vm_writev doesn't modify
    // the local memory.
    struct iovec local = { .iov_base = (char*)python_code, .iov_len=len };
    struct iovec remote = { .iov_base = (void*)mapped_addr, .iov_len=len };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) != len) {
        perror("process_vm_writev");
        return ATT_FAIL;
    }

    // We tell Py_AddPendingCall to call into this function that only
    // does a trap.

    word_of_instr_t brk_and_ret = {
        #if defined(__aarch64__)
            .u32s[0] = DEBUG_TRAP_INSTR,
            .u32s[1] = 0xd65f03c0,  /* ret */
        #elif defined(__x86_64__)
            .c_bytes[0] = DEBUG_TRAP_INSTR,
            .c_bytes[1] = 0xc3, /* retq */
        #elif defined(__riscv)
            .u32s[0] = DEBUG_TRAP_INSTR,
            .u32s[1] = 0x00008067,  /* ret (jalr x0,x1,0) */
        #endif
    };
    if (-1 == ptrace(PTRACE_POKETEXT, tid, (void*)(libc_start_addr + sizeof(void*)),
                brk_and_ret.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        return ATT_UNKNOWN_STATE;
    }

    if ((err = add_pending_in_target(pid, tid, libc_start_addr,
                    (libc_start_addr + sizeof(void*)), 0)) != 0) {
        log_err("adding pending call in target failed");
        return err;
    }
    log_dbg("added pending call in target");

    // We resume the thread that stopped, so, they should all be running now.
    if (ptrace(PTRACE_CONT, tid, 0, 0) == -1) {
        perror("ptrace(PTRACE_CONT, ...)");
        return ATT_UNKNOWN_STATE;
    }

    // tid will now switch to the main thread ID.
    if ((tid = wait_for_stop(-1, SIGTRAP, NULL)) == -1) {
        if (errno != EINTR) {
            log_err("wait_for_stop failed");
            return ATT_UNKNOWN_STATE;
        }
        struct tgt_thrd main_thrd = { .tid = pid, };
        if ((err = interrupt_threads(&main_thrd, 1)) != 0) {
            return ATT_UNKNOWN_STATE;
        }
        *mtid = pid;
        // Since this was an EINTR... we replace the trap with the ret in order
        // to null out the breakpoint...
        word_of_instr_t ret_and_ret = {
            #if defined(__aarch64__)
                .u32s[0] = 0xd65f03c0,
                .u32s[1] = 0xd65f03c0,  /* ret */
            #elif defined(__x86_64__)
                .c_bytes[0] = 0xc3,
                .c_bytes[1] = 0xc3, /* retq */
            #elif defined(__riscv)
                .u32s[0] = 0x00008067,
                .u32s[1] = 0x00008067,  /* ret (jalr x0,x1,0) */
            #endif
        };
        if (-1 == ptrace(PTRACE_POKETEXT, pid,
                    (void*)(libc_start_addr + sizeof(void*)),
                    ret_and_ret.u64)) {
            perror("ptrace (stubbing out breakpoint)");
            return ATT_UNKNOWN_STATE;
        }
        return ATT_INTERRUPTED;
    }
    *mtid = tid;
    log_dbg("main thread stopped, tid=%d", tid);

    if ((err = call_pyrun_simplestring(pid, tid, libc_start_addr, mapped_addr))
            != 0) {
        // we need to continue to restore the PC and the overwritten libc
    }
    log_dbg("have run PyRun_SimpleString");

    int err2 = set_pc(tid,
            libc_start_addr + sizeof(void*) + sizeof(DEBUG_TRAP_INSTR), 0);
    if (err == ATT_UNKNOWN_STATE || err2 == -1) {
        return ATT_UNKNOWN_STATE;
    }
    log_dbg("bumped PC past breakpoint");

    // TODO: restore libc+8

    // TODO: munmap
    return err;
}

int
attach_and_execute(const int pid, const char* python_code)
{
    int err = 0;

    // TODO: check python_code size < page size

    int nthreads = 0;
    err = get_threads(pid, NULL, &nthreads);
    if (err != 0) {
        return ATT_FAIL;
    }
    enum { MAX_THRDS = 16 };
    if (nthreads > MAX_THRDS) {
        log_err("target has %d threads, multiple target threads are not yet "
                "supported", nthreads);
        return ATT_FAIL;
    }
    if (nthreads > 0) {
        // Specifically it doesn't work if the main thread doesn't get time
        // and the tracing doesn't work for non-main on <3.12
        log_err("target has %d threads, this may not work correctly", nthreads);
    }

    struct tgt_thrd thrds[MAX_THRDS] = {};
    err = get_threads(pid, thrds, &nthreads);
    if (err != 0) {
        return err;
    }
    if (nthreads > MAX_THRDS) {
        log_err("changing number of threads");
        return ATT_FAIL;
    }

    uintptr_t breakpoint_addr = find_pyfn(pid, SAFE_POINT);
    if (breakpoint_addr == 0) {
        log_err("unable to find %s", SAFE_POINT);
        return ATT_FAIL;
    }
    log_dbg(SAFE_POINT " = %lx", breakpoint_addr);


    err = attach_threads(thrds, nthreads);
    if (err != 0) {
        return err;
    }

    // TODO: consider setting a hardware breakpoint instead.

    word_of_instr_t saved_instrs = {};
    if (save_instrs(pid, &saved_instrs, breakpoint_addr) != 0) {
        err = ATT_FAIL;
        goto detach;
    }

    // Note aarch64 has 64-bit words but 32-bit instructions so
    // we only write to the first four bytes.
    word_of_instr_t breakpoint_instrs = saved_instrs;
    #if defined(__aarch64__) || defined(__riscv)
        breakpoint_instrs.u32s[0] = DEBUG_TRAP_INSTR;
    #elif defined(__x86_64__)
        breakpoint_instrs.c_bytes[0] = DEBUG_TRAP_INSTR;
    #endif
    if (-1 == ptrace(PTRACE_POKETEXT, pid, breakpoint_addr,
                breakpoint_instrs.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        err = ATT_FAIL;
        goto detach;
    }

    // TODO: we need to protect ourselves from signals here
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

        if (-1 == ptrace(PTRACE_POKETEXT, pid, breakpoint_addr,
                    saved_instrs.u64)) {
            perror("ptrace (restoring instructions at breakpoint)");
            err = ATT_UNKNOWN_STATE;
            goto detach;
        }
        fprintf(stderr, "attacher: cancelled.\n");
        err = ATT_INTERRUPTED;
        goto detach;
    }
    log_dbg("have a target thread at breakpoint: tid=%d", tid);

    // TODO: we should check the PC that it's at (or just after) the
    // breakpoint.

    // Restore patched code
    if (-1 == ptrace(PTRACE_POKETEXT, tid, breakpoint_addr,
                saved_instrs.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        err = ATT_UNKNOWN_STATE;
        goto detach;
    }

    // Back the instruction pointer back to the breakpoint_addr for
    // architectures where the instruction pointer still increments on the
    // trap. Note: an illegal instruction, ud2, would not have this problem
    // but then we'd have to adapt our signal handling code ... Let's compare
    // HW breakpoints before deciding.
#if defined(__x86_64__)
    if (-1 == set_pc(tid, breakpoint_addr)) {
        err = ATT_UNKNOWN_STATE; /* until we succeed with the next the
                                    instruction pointer, we're in a bad
                                    state */
        goto detach;
    }
#endif // defined(__x86_64__)

    // Main python thread.
    pid_t mtid = -1;
    if ((err = exec_python_code(pid, tid, python_code, &mtid)) != 0) {
        // ... actually it's verbose enough
        if (err != ATT_INTERRUPTED) {
            goto detach;
        }
    }

    // stop the non main threads so that they can be detached
    for (int i = 0; i < nthreads; i++) {
        __auto_type t = &thrds[i];
        if (t->tid != mtid) {
            if (ptrace(PTRACE_INTERRUPT, t->tid, 0, 0) == -1) {
                perror("ptrace interrupt");
                continue;
            }
            if (wait_for_stop(t->tid, SIGTRAP, &t->wstatus) == -1) {
                continue;
            }
        }
    }

detach:
    if (detach_threads(thrds, nthreads) != 0) {
        err = ATT_UNKNOWN_STATE;
    }
    return err;
}
