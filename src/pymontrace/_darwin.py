import ctypes
import sys
from ctypes.util import find_library
from typing import cast

libc = ctypes.cdll.LoadLibrary(cast(str, find_library("c")))

CTL_KERN = 1
KERN_PROC = 14
KERN_PROC_PID = 1


def kern_proc_info(pid: int):
    FourInts = ctypes.c_int * 4
    mib = FourInts(CTL_KERN, KERN_PROC, KERN_PROC_PID, pid)
    cb = ctypes.c_int()   # count bytes
    libc.sysctl(mib, len(mib), None, ctypes.byref(cb), None, 0)
    buf = ctypes.create_string_buffer(cb.value)
    libc.sysctl(mib, len(mib), buf, ctypes.byref(cb), None, 0)
    return buf


# Obviously, if/as we ever want to get more info out, it would make
# sense to rewrite in C, describe the actual structure, use cython...
# Probably there are lots of options.
def get_euid(kproc_info: ctypes.Array):
    """
    #include <stddef.h> // offsetof
    #include <stdio.h>
    #include <sys/sysctl.h>
    int main()
    {
        printf("offset = %zu\\n",
                offsetof(struct kinfo_proc, kp_eproc.e_ucred.cr_uid));
        struct kinfo_proc *info;
        printf("sizeof(uid_t) = %zu\\n", sizeof(info->kp_eproc.e_ucred.cr_uid));
    }
    """
    return int.from_bytes(kproc_info.raw[420:424], sys.byteorder)
