# list of commonly used constants
# cat /usr/include/asm/unistd_32.h | grep define | cut -b14- | sed -e "s/^/\"/;s/ /\": /;s/\$/,/"
linux_x86_syscalls = {
	"restart_syscall": 0,
	"exit": 1,
	"fork": 2,
	"read": 3,
	"write": 4,
	"open": 5,
	"close": 6,
	"waitpid": 7,
	"creat": 8,
	"link": 9,
	"unlink": 10,
	"execve": 11,
	"chdir": 12,
	"time": 13,
	"mknod": 14,
	"chmod": 15,
	"lchown": 16,
	"break": 17,
	"oldstat": 18,
	"lseek": 19,
	"getpid": 20,
	"mount": 21,
	"umount": 22,
	"setuid": 23,
	"getuid": 24,
	"stime": 25,
	"ptrace": 26,
	"alarm": 27,
	"oldfstat": 28,
	"pause": 29,
	"utime": 30,
	"stty": 31,
	"gtty": 32,
	"access": 33,
	"nice": 34,
	"ftime": 35,
	"sync": 36,
	"kill": 37,
	"rename": 38,
	"mkdir": 39,
	"rmdir": 40,
	"dup": 41,
	"pipe": 42,
	"times": 43,
	"prof": 44,
	"brk": 45,
	"setgid": 46,
	"getgid": 47,
	"signal": 48,
	"geteuid": 49,
	"getegid": 50,
	"acct": 51,
	"umount2": 52,
	"lock": 53,
	"ioctl": 54,
	"fcntl": 55,
	"mpx": 56,
	"setpgid": 57,
	"ulimit": 58,
	"oldolduname": 59,
	"umask": 60,
	"chroot": 61,
	"ustat": 62,
	"dup2": 63,
	"getppid": 64,
	"getpgrp": 65,
	"setsid": 66,
	"sigaction": 67,
	"sgetmask": 68,
	"ssetmask": 69,
	"setreuid": 70,
	"setregid": 71,
	"sigsuspend": 72,
	"sigpending": 73,
	"sethostname": 74,
	"setrlimit": 75,
	"getrlimit": 76,
	"getrusage": 77,
	"gettimeofday": 78,
	"settimeofday": 79,
	"getgroups": 80,
	"setgroups": 81,
	"select": 82,
	"symlink": 83,
	"oldlstat": 84,
	"readlink": 85,
	"uselib": 86,
	"swapon": 87,
	"reboot": 88,
	"readdir": 89,
	"mmap": 90,
	"munmap": 91,
	"truncate": 92,
	"ftruncate": 93,
	"fchmod": 94,
	"fchown": 95,
	"getpriority": 96,
	"setpriority": 97,
	"profil": 98,
	"statfs": 99,
	"fstatfs": 100,
	"ioperm": 101,
	"socketcall": 102,
	"syslog": 103,
	"setitimer": 104,
	"getitimer": 105,
	"stat": 106,
	"lstat": 107,
	"fstat": 108,
	"olduname": 109,
	"iopl": 110,
	"vhangup": 111,
	"idle": 112,
	"vm86old": 113,
	"wait4": 114,
	"swapoff": 115,
	"sysinfo": 116,
	"ipc": 117,
	"fsync": 118,
	"sigreturn": 119,
	"clone": 120,
	"setdomainname": 121,
	"uname": 122,
	"modify_ldt": 123,
	"adjtimex": 124,
	"mprotect": 125,
	"sigprocmask": 126,
	"create_module": 127,
	"init_module": 128,
	"delete_module": 129,
	"get_kernel_syms": 130,
	"quotactl": 131,
	"getpgid": 132,
	"fchdir": 133,
	"bdflush": 134,
	"sysfs": 135,
	"personality": 136,
	"afs_syscall": 137,
	"setfsuid": 138,
	"setfsgid": 139,
	"_llseek": 140,
	"getdents": 141,
	"_newselect": 142,
	"flock": 143,
	"msync": 144,
	"readv": 145,
	"writev": 146,
	"getsid": 147,
	"fdatasync": 148,
	"_sysctl": 149,
	"mlock": 150,
	"munlock": 151,
	"mlockall": 152,
	"munlockall": 153,
	"sched_setparam": 154,
	"sched_getparam": 155,
	"sched_setscheduler": 156,
	"sched_getscheduler": 157,
	"sched_yield": 158,
	"sched_get_priority_max": 159,
	"sched_get_priority_min": 160,
	"sched_rr_get_interval": 161,
	"nanosleep": 162,
	"mremap": 163,
	"setresuid": 164,
	"getresuid": 165,
	"vm86": 166,
	"query_module": 167,
	"poll": 168,
	"nfsservctl": 169,
	"setresgid": 170,
	"getresgid": 171,
	"prctl": 172,
	"rt_sigreturn": 173,
	"rt_sigaction": 174,
	"rt_sigprocmask": 175,
	"rt_sigpending": 176,
	"rt_sigtimedwait": 177,
	"rt_sigqueueinfo": 178,
	"rt_sigsuspend": 179,
	"pread64": 180,
	"pwrite64": 181,
	"chown": 182,
	"getcwd": 183,
	"capget": 184,
	"capset": 185,
	"sigaltstack": 186,
	"sendfile": 187,
	"getpmsg": 188,
	"putpmsg": 189,
	"vfork": 190,
	"ugetrlimit": 191,
	"mmap2": 192,
	"truncate64": 193,
	"ftruncate64": 194,
	"stat64": 195,
	"lstat64": 196,
	"fstat64": 197,
	"lchown32": 198,
	"getuid32": 199,
	"getgid32": 200,
	"geteuid32": 201,
	"getegid32": 202,
	"setreuid32": 203,
	"setregid32": 204,
	"getgroups32": 205,
	"setgroups32": 206,
	"fchown32": 207,
	"setresuid32": 208,
	"getresuid32": 209,
	"setresgid32": 210,
	"getresgid32": 211,
	"chown32": 212,
	"setuid32": 213,
	"setgid32": 214,
	"setfsuid32": 215,
	"setfsgid32": 216,
	"pivot_root": 217,
	"mincore": 218,
	"madvise": 219,
	"getdents64": 220,
	"fcntl64": 221,
	"gettid": 224,
	"readahead": 225,
	"setxattr": 226,
	"lsetxattr": 227,
	"fsetxattr": 228,
	"getxattr": 229,
	"lgetxattr": 230,
	"fgetxattr": 231,
	"listxattr": 232,
	"llistxattr": 233,
	"flistxattr": 234,
	"removexattr": 235,
	"lremovexattr": 236,
	"fremovexattr": 237,
	"tkill": 238,
	"sendfile64": 239,
	"futex": 240,
	"sched_setaffinity": 241,
	"sched_getaffinity": 242,
	"set_thread_area": 243,
	"get_thread_area": 244,
	"io_setup": 245,
	"io_destroy": 246,
	"io_getevents": 247,
	"io_submit": 248,
	"io_cancel": 249,
	"fadvise64": 250,
	"exit_group": 252,
	"lookup_dcookie": 253,
	"epoll_create": 254,
	"epoll_ctl": 255,
	"epoll_wait": 256,
	"remap_file_pages": 257,
	"set_tid_address": 258,
	"timer_create": 259,
	"timer_settime": 260,
	"timer_gettime": 261,
	"timer_getoverrun": 262,
	"timer_delete": 263,
	"clock_settime": 264,
	"clock_gettime": 265,
	"clock_getres": 266,
	"clock_nanosleep": 267,
	"statfs64": 268,
	"fstatfs64": 269,
	"tgkill": 270,
	"utimes": 271,
	"fadvise64_64": 272,
	"vserver": 273,
	"mbind": 274,
	"get_mempolicy": 275,
	"set_mempolicy": 276,
	"mq_open": 277,
	"mq_unlink": 278,
	"mq_timedsend": 279,
	"mq_timedreceive": 280,
	"mq_notify": 281,
	"mq_getsetattr": 282,
	"kexec_load": 283,
	"waitid": 284,
	"add_key": 286,
	"request_key": 287,
	"keyctl": 288,
	"ioprio_set": 289,
	"ioprio_get": 290,
	"inotify_init": 291,
	"inotify_add_watch": 292,
	"inotify_rm_watch": 293,
	"migrate_pages": 294,
	"openat": 295,
	"mkdirat": 296,
	"mknodat": 297,
	"fchownat": 298,
	"futimesat": 299,
	"fstatat64": 300,
	"unlinkat": 301,
	"renameat": 302,
	"linkat": 303,
	"symlinkat": 304,
	"readlinkat": 305,
	"fchmodat": 306,
	"faccessat": 307,
	"pselect6": 308,
	"ppoll": 309,
	"unshare": 310,
	"set_robust_list": 311,
	"get_robust_list": 312,
	"splice": 313,
	"sync_file_range": 314,
	"tee": 315,
	"vmsplice": 316,
	"move_pages": 317,
	"getcpu": 318,
	"epoll_pwait": 319,
	"utimensat": 320,
	"signalfd": 321,
	"timerfd_create": 322,
	"eventfd": 323,
	"fallocate": 324,
	"timerfd_settime": 325,
	"timerfd_gettime": 326,
	"signalfd4": 327,
	"eventfd2": 328,
	"epoll_create1": 329,
	"dup3": 330,
	"pipe2": 331,
	"inotify_init1": 332,
	"preadv": 333,
	"pwritev": 334,
	"rt_tgsigqueueinfo": 335,
	"perf_event_open": 336,
	"recvmmsg": 337,
	"fanotify_init": 338,
	"fanotify_mark": 339,
	"prlimit64": 340,
	"name_to_handle_at": 341,
	"open_by_handle_at": 342,
	"clock_adjtime": 343,
	"syncfs": 344,
	"sendmmsg": 345,
	"setns": 346,
	"process_vm_readv": 347,
	"process_vm_writev": 348,
	"kcmp": 349,
	"finit_module": 350,
	"sched_setattr": 351,
	"sched_getattr": 352,
	"renameat2": 353,
	"seccomp": 354,
}