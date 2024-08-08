#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
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

#include <linux/elf.h>
#include <sys/uio.h>

#include <assert.h>

#include "attacher.h"

#define SAFE_POINT  "PyEval_SaveThread"

// this is what gcc gives for __builtin_trap()
//    brk    #0x3e8
#define DEBUG_TRAP_INSTR    ((uint32_t)0xd4207d00)


#define log_err(fmt, ...) fprintf(stderr, "[error]: " fmt "\n", ##__VA_ARGS__)

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
        perror("fopen"); // need mapspath ?
        return 0;
    }

    size_t len = 0;
    char* line = NULL;
    while (getline(&line, &len, f) != -1) {
        if (!strstr(line, "/libc.so")) {
            continue;
        }
        proc_map_t map;
        if (parse_proc_map(line, &map) != 0) {
            log_err("failed parsing a procmap line");
            continue;
        }
        // We only care about code
        if (!perms_has_exec(map)) {
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


static uintptr_t
find_symbol(pid_t pid, const char* symbol, const char* fnsrchstr)
{
    uintptr_t symbol_addr = 0;
    char mapspath[PATH_MAX];
    snprintf(mapspath, PATH_MAX, "/proc/%d/maps", pid);

    FILE* f = fopen(mapspath, "r");
    if (!f) {
        perror("fopen"); // need mapspath ?
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
        if (!perms_has_exec(map)) {
            continue;
        }

        elfsym_info_t es_info;
        int err = elf_find_symbol(map.pathname, symbol, &es_info);
        if (err == ESRCH) {
            continue;
        }
        if (err != 0) {
            fprintf(stderr, "attacher: error reading %s (%d)",
                    map.pathname, err);
            continue;
        }

        if ((es_info.section_addr >= map.addr_start &&
                    es_info.section_addr < map.addr_end) &&
                (es_info.sym_addr >= map.addr_start &&
                 es_info.sym_addr < map.addr_end)) {
            // Seems very likely this mapping has not be ASLR'd.
            // Maybe that's how things are with exec files.

            symbol_addr = es_info.sym_addr;
        } else if (map.offset == 0 && (
                    map.addr_start + es_info.sym_addr < map.addr_end)) {
            // DYN
            // TODO: actually check the address in the program headers
            symbol_addr = map.addr_start + es_info.sym_addr;
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
call_mmap_in_target(pid_t pid, pid_t tid, uintptr_t* addr)
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

    // ... we don't *need* to save the instructions since, in this case
    // we've already saved them in attach_and_exec.
    word_of_instr_t saved_instrs = {};

    struct iovec local = {
        .iov_base = saved_instrs.c_bytes,
        .iov_len = sizeof saved_instrs,
    };
    struct iovec remote = {
        .iov_base = (void*)user_regs.pc,
        .iov_len = sizeof saved_instrs,
    };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != remote.iov_len) {
        perror("process_vm_readv");
        return ATT_FAIL;
    }

    word_of_instr_t syscall_and_brk = {
        .u32s[0] = 0xd4000001, /* svc	#0 */
        .u32s[1] = DEBUG_TRAP_INSTR,
    };
    if (-1 == ptrace(PTRACE_POKETEXT, tid, (void*)user_regs.pc,
                syscall_and_brk.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        return ATT_FAIL;
    }

    // Setup registers for mmap call
    struct user_regs_struct urmmap = user_regs;

    urmmap.regs[8] = SYS_mmap;
    urmmap.regs[0] = 0; // addr
    urmmap.regs[1] = sysconf(_SC_PAGESIZE); // length
    urmmap.regs[2] = PROT_READ | PROT_WRITE; // prot
    urmmap.regs[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    urmmap.regs[4] = -1; // fd
    urmmap.regs[5] = 0; // offset

    struct iovec iov_mmap = {.iov_base = &urmmap, .iov_len = sizeof urmmap};

    if (-1 == ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov_mmap)) {
        perror("ptrace(PTRACE_SETREGSET, ...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_regs;
    }

    if (ptrace(PTRACE_CONT, tid, 0, 0) == -1) {
        perror("ptrace(PTRACE_CONT, ...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_regs;
    }

    // This waits until the next signal, which will be the breakpoint
    // hopefully. But maybe it's the syscall?
    int wstatus;
    if ((tid = waitpid(pid, &wstatus, 0)) == -1) {
        perror("waitpid");
        err = ATT_UNKNOWN_STATE;
        goto restore_regs;
    }
    if (!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGTRAP) {
        // TODO, loop until correct signal, or use the newer apis
        fprintf(stderr, "WIFSTOPPED(status) = %d, WSTOPSIG(wstatus)= %d\n",
                WIFSTOPPED(wstatus), WSTOPSIG(wstatus));
    }

    if (-1 == ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov_mmap)) {
        perror("ptrace(PTRACE_GETREGSET, ...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_regs;
    }

    // from linux/tools/include/nolibc/sys.h
    void* ret = (void*)urmmap.regs[0];
    if ((unsigned long)ret >= -4095UL) {
        errno = -(long)ret;
        perror("mmap_in_target");
        err = ATT_FAIL;
    }

    *addr = (uintptr_t)ret;

    // todo: restore instructions?

restore_regs:

    if (-1 == ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov)) {
        perror("ptrace(PTRACE_SETREGSET,...)");
        return ATT_UNKNOWN_STATE;
    }

    return err;
}


static ssize_t
call_pyfn_in_target(pid_t pid, pid_t tid, uintptr_t fn_addr, uintptr_t buf)
{
    // not sure it really makes sense to pass in the fn_addr since
    // this will only work for functions of a single string argument...
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

    // There is a build-id at the start of glibc that we can overwrite
    // temporarily (idea from the readme of kubo/injector)
    uintptr_t libc_start_addr = find_libc_start(pid);
    if (libc_start_addr == 0) {
        fprintf(stderr, "could not find libc\n");
        return ATT_FAIL;
    }

    uintptr_t add_pending_call_addr = find_pyfn(pid, "Py_AddPendingCall");

    if (add_pending_call_addr == 0) {
        log_err("failed to find symbol Py_AddPendingCall");
        return ATT_FAIL;
    }

    word_of_instr_t saved_instrs = {};

    struct iovec local = {
        .iov_base = saved_instrs.c_bytes,
        .iov_len = sizeof saved_instrs,
    };
    struct iovec remote = {
        .iov_base = (void*)libc_start_addr,
        .iov_len = sizeof saved_instrs,
    };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != remote.iov_len) {
        perror("process_vm_readv");
        return ATT_FAIL;
    }

    word_of_instr_t indirect_call_and_brk = {
        .u32s[0] = 0xd63f0200,  /* blr	x16 */
        .u32s[1] = DEBUG_TRAP_INSTR,
    };
    if (-1 == ptrace(PTRACE_POKETEXT, tid, (void*)libc_start_addr,
                indirect_call_and_brk.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        return ATT_FAIL;
    }

    // Setup registers for call
    struct user_regs_struct urcall = user_regs;

    urcall.regs[0] = fn_addr;
    urcall.regs[1] = buf;
    urcall.regs[16] = add_pending_call_addr;
    urcall.pc = libc_start_addr;

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

    // This waits until the next signal, which will be the breakpoint
    // hopefully.
    int wstatus;
    if ((tid = waitpid(pid, &wstatus, 0)) == -1) {
        perror("waitpid");
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }
    if (!WIFSTOPPED(wstatus)) {
        fprintf(stderr, "TODO: not WIFSTOPPED(status)\n");
    }

    if (-1 == ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov_call)) {
        perror("ptrace(PTRACE_GETREGSET,...)");
        err = ATT_UNKNOWN_STATE;
        goto restore_instuctions;
    }

    if (urcall.regs[0] != 0) {
        log_err("running python code failed");
    }

restore_instuctions:
    if (-1 == ptrace(PTRACE_POKETEXT, tid, (void*)libc_start_addr,
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


int
attach_and_execute(int pid, const char* python_code)
{
    int err = 0;

    // TODO: check python_code size < page size

    uint64_t breakpoint_addr = find_pyfn(pid, SAFE_POINT);
    if (breakpoint_addr == 0) {
        fprintf(stderr, "unable to find %s\n", SAFE_POINT);
        return ATT_FAIL;
    }

    // TODO: consider using PTRACE_SEIZE and then PTRACE_INTERRUPT
    if (-1 == ptrace(PTRACE_ATTACH, pid, 0, 0)) {
        perror("ptrace");
        return ATT_FAIL;
    }

    // TODO: timeout
    // Use waitid?
    int wstatus = 0;
    pid_t tid;
    if ((tid = waitpid(pid, &wstatus, 0)) == -1) {
        perror("waitpid");
        return ATT_UNKNOWN_STATE;
    }

    // TODO: loop and resupply signals until it's the correct one?
    if (!WIFSTOPPED(wstatus)) {
        fprintf(stderr, "WIFEXITED(wstatus)=%d, WIFSIGNALED(wstatus)=%d\n",
                WIFEXITED(wstatus), WIFSIGNALED(wstatus));
        return ATT_UNKNOWN_STATE;
    }

    // TODO: write simple wrapper for this
    word_of_instr_t saved_instrs = {};
    struct iovec local = {
        .iov_base = saved_instrs.c_bytes,
        .iov_len = sizeof saved_instrs,
    };
    struct iovec remote = {
        .iov_base = (void*)breakpoint_addr,
        .iov_len = sizeof saved_instrs,
    };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != remote.iov_len) {
        perror("process_vm_readv");
        if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1){
            return ATT_UNKNOWN_STATE;
        }
        return ATT_FAIL;
    }

    // Note aarch64 has 64-bit words but 32-bit instructions so
    // we only write to the first four bytes.
    word_of_instr_t breakpoint_instrs = {
        .u32s[0] = DEBUG_TRAP_INSTR,
        .u32s[1] = saved_instrs.u32s[1],
    };
    if (-1 == ptrace(PTRACE_POKETEXT, tid, breakpoint_addr,
                breakpoint_instrs.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        return ATT_FAIL;
    }


    fprintf(stderr, "Waiting for process to reach safepoint...\n");
    if (ptrace(PTRACE_CONT, tid, 0, 0) == -1) {
        perror("ptrace(PTRACE_CONT, ...)");
        return ATT_UNKNOWN_STATE;
    }

    // This waits until the next signal, which will be the breakpoint
    // hopefully.
    if ((tid = waitpid(pid, &wstatus, 0)) == -1) {
        perror("waitpid");
        return ATT_UNKNOWN_STATE;
    }
    if (!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGTRAP) {
        // TODO, loop until correct signal, or use the newer apis
        fprintf(stderr, "WIFSTOPPED(status) = %d, WSTOPSIG(wstatus)= %d\n",
                WIFSTOPPED(wstatus), WSTOPSIG(wstatus));
    }


    // This is the point at which we can start to do our work.
    uintptr_t mapped_addr = 0;
    if (call_mmap_in_target(pid, tid, &mapped_addr) != 0) {
        fprintf(stderr, "call_mmap_in_target failed\n");
        err = ATT_FAIL;
        goto restore_text;
    }


    {
        ssize_t len = (1 + strlen(python_code));
        // safe to cast away const here as process_vm_writev doesn't modify
        // the local memory.
        struct iovec local = { .iov_base = (char*)python_code, .iov_len=len };
        struct iovec remote = { .iov_base = (void*)mapped_addr, .iov_len=len };
        if (process_vm_writev(pid, &local, 1, &remote, 1, 0) != len) {
            perror("process_vm_writev");
            err = ATT_FAIL;
            goto restore_text;
        }
    }


    uint64_t PyRun_SimpleString = find_pyfn(pid, "PyRun_SimpleString");
    if (PyRun_SimpleString == 0) {
        fprintf(stderr, "unable to find %s\n", "PyRun_SimpleString");
        err = ATT_FAIL;
        goto restore_text;
    }

    if (call_pyfn_in_target(pid, tid, PyRun_SimpleString, mapped_addr) != 0) {
        fprintf(stderr, "call PyRun_SimpleString in target failed\n");
        err = ATT_FAIL;
    }

    // TODO: munmap (requires setting the breakpoint in the function passed
    // to Py_AddPendingCall)

restore_text:

    if (-1 == ptrace(PTRACE_POKETEXT, tid, breakpoint_addr,
                saved_instrs.u64)) {
        perror("ptrace(PTRACE_POKETEXT, ...)");
        return ATT_UNKNOWN_STATE;
    }

    if (-1 == ptrace(PTRACE_DETACH, pid, 0, 0)) {
        perror("ptrace(PTRACE_DETACH,...)");
        return ATT_UNKNOWN_STATE;
    }
    return err;
}
