### bVisor - Embedded Bash Sandbox for Agents

bVisor is an SDK and runtime for safely executing bash commands locally, without the need for remote sandboxes or local VMs/containers. 

Inspired by [gVisor](https://github.com/google/gVisor), bVisor runs programs directly on the host machine, providing isolation by intercepting and virtualizing [Linux syscalls](https://en.wikipedia.org/wiki/System_call) from userspace. 

Unlike gVisor, bVisor is built to run directly in your application, spinning up sandboxes in ~2 milliseconds. This makes it ideal for ephemeral tasks commonly performed by LLM agents, such as code execution or filesystem operations.

**Status**: bVisor is an early proof-of-concept and should not yet be used in production. If you detect any discrepancies between bVisor's behavior and the linux kernel, please file an issue.

**Compatibility**: bVisor currently ships for Linux hosts only, with support for ARM and X86 architectures and glibc/musl ABIs.

## Usage

The bVisor runtime ships wrapped in a Typescript SDK, installed via npm.

```bash
npm install bvisor
```

Example usage:
```typescript
import { Sandbox } from "bvisor";

const sb = new Sandbox();
const output = sb.runCmd("echo 'Hello, world!'");

console.log(await output.stdout());
```

This executes `echo 'Hello, world!'` inside a sandbox.

Filesystem operations are safely virtualized:
```typescript
sb.runCmd("echo 'Hello, world!' > /tmp/test.txt"); // only visible from this sandbox
```

Unsafe commands are blocked:
```typescript
sb.runCmd("chroot /tmp"); // error
```

Python SDK and CLI are also planned.

## Examples

Here are a selection of full examples which currently work in bVisor:
- [Hello World](src/sdks/node/examples/hello-world.ts) - Run your first command in the sandbox
- [Running Python](src/sdks/node/examples/python-hello.ts) - Write and execute a Python script 
- [Testing Sandbox Boundaries](src/sdks/node/examples/sandbox-boundaries.ts) - See how the sandbox handles host fingerprinting, blocked paths, and filesystem isolation
- [Filesystem Operations](src/sdks/node/examples/nested-dirs.ts) - Demonstrate directory creation, file operations, running scripts

## Architecture

bVisor is built on [Seccomp user notifier](https://man7.org/linux/man-pages/man2/seccomp.2.html), a Linux kernel feature that allows userspace processes to intercept and optionally handle syscalls from a child process. This allows bVisor to block or mock the kernel API (such as filesystem read/write, network access, etc.) to ensure the child process remains sandboxed.

Other than the overhead of syscall emulation, child processes run natively.

bVisor is imageless, meaning it does not require a base image to run. It runs with direct visibility to the host filesystem. This allows system dependencies such as `npm` to work out of the box. Isolation is achieved via a copy-on-write overlay on top of the host filesystem. Files opened with write flags are copied to a sandbox-local directory. Read-only files are passed through to the real filesystem.

## Syscall Support

Every Linux syscall falls into one of four categories in bVisor:

#### Virtualized
Syscalls are intercepted and handled in userspace by the bVisor virtual kernel.

| | Syscalls |
|-|----------|
| File I/O | `openat`, `close`, `read`, `write`, `readv`, `writev`, `lseek`, `dup`, `dup3`, `fcntl`, `ioctl`, `pipe2` |
| File metadata | `fstat`, `fstatat64`, `faccessat`, `utimensat`, `fchmodat` |
| Directory | `getcwd`, `chdir`, `fchdir`, `getdents64`, `mkdirat`, `unlinkat`, `symlinkat`, `readlinkat` |
| Process | `getpid`, `getppid`, `gettid`, `kill`, `tkill`, `exit`, `exit_group`, `execve` |
| Networking | `socket`, `socketpair`, `connect`, `shutdown`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg` |
| System info | `uname`, `sysinfo` |
| Events | `eventfd2` |

Note that bVisor may still call into the underlying kernel to virtualize any given syscall.

#### Passthrough
Syscalls are forwarded to the kernel unmodified. These syscalls are process-local or read-only and do not require any virtualization.

| | Syscalls |
|-|----------|
| Process | `clone`, `wait4`, `waitid`, `set_tid_address` |
| Identity | `getuid`, `geteuid`, `getgid`, `getegid` |
| Memory | `brk`, `mmap`, `mprotect`, `munmap`, `mremap`, `madvise` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `rt_sigsuspend`, `rt_sigpending`, `rt_sigtimedwait`, `sigaltstack`, `restart_syscall` |
| Time | `clock_gettime`, `clock_getres`, `gettimeofday`, `nanosleep`, `clock_nanosleep` |
| Sync | `futex`, `futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv`, `set_robust_list`, `rseq` |
| Random | `getrandom` |

#### Blocked
Syscalls are blocked and return `ENOSYS` or `EPERM`. These could allow sandbox escape or privilege escalation.

| | Syscalls |
|-|----------|
| Privilege escalation | `ptrace`, `mount`, `umount2`, `chroot`, `pivot_root`, `reboot`, `setns`, `unshare`, `seccomp`, `bpf` |
| Cross-process memory | `process_vm_readv`, `process_vm_writev` |
| Kernel modules | `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module` |
| Resource control | `setrlimit`, `prlimit64` |
| Execution domain | `personality` |
| Server sockets | `bind`, `listen`, `accept`, `accept4` |

#### Roadmap
Not yet handled but likely necessary for Bash compatibility. Currently return `ENOSYS`.

| | Syscalls |
|-|----------|
| System info | `getrlimit`, `getrusage` |
| Resource limits | not started (cgroups) |

<details>
<summary>See full list of other unhandled syscalls (~240)</summary>

| | Syscalls |
|-|----------|
| File I/O | `pread64`, `pwrite64`, `preadv`, `pwritev`, `preadv2`, `pwritev2`, `sendfile`, `splice`, `tee`, `vmsplice`, `readahead`, `copy_file_range` |
| File metadata | `statx`, `statfs`, `fstatfs`, `truncate`, `ftruncate`, `fallocate`, `fadvise64`, `flock`, `fchmod`, `fchmodat2`, `fchown`, `fchownat`, `faccessat2`, `cachestat` |
| Directory | `mknodat`, `linkat`, `renameat`, `renameat2` |
| Process | `execveat`, `clone3`, `tgkill`, `prctl`, `pidfd_open`, `pidfd_getfd`, `pidfd_send_signal`, `kcmp`, `userfaultfd` |
| System info | `syslog`, `umask`, `getcpu`, `acct`, `vhangup`, `sethostname`, `setdomainname` |
| Identity (write) | `setuid`, `setgid`, `setreuid`, `setregid`, `setresuid`, `getresuid`, `setresgid`, `getresgid`, `setfsuid`, `setfsgid`, `getgroups`, `setgroups`, `setpriority`, `getpriority` |
| Session/pgid | `setpgid`, `getpgid`, `getsid`, `setsid` |
| Memory | `msync`, `mlock`, `munlock`, `mlockall`, `munlockall`, `mincore`, `remap_file_pages`, `mbind`, `get_mempolicy`, `set_mempolicy`, `set_mempolicy_home_node`, `migrate_pages`, `move_pages`, `process_madvise`, `mlock2`, `memfd_create`, `memfd_secret`, `map_shadow_stack`, `pkey_mprotect`, `pkey_alloc`, `pkey_free`, `mseal`, `membarrier`, `process_mrelease` |
| Signals | `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `signalfd4` |
| Time | `clock_settime`, `clock_adjtime`, `settimeofday`, `adjtimex`, `getitimer`, `setitimer`, `times`, `timer_create`, `timer_gettime`, `timer_getoverrun`, `timer_settime`, `timer_delete`, `timerfd_create`, `timerfd_settime`, `timerfd_gettime` |
| Networking | `getsockname`, `getpeername`, `setsockopt`, `getsockopt`, `sendmmsg`, `recvmmsg` |
| Polling/events | `epoll_create1`, `epoll_ctl`, `epoll_pwait`, `epoll_pwait2`, `pselect6`, `ppoll` |
| File sync | `sync`, `fsync`, `fdatasync`, `sync_file_range`, `syncfs` |
| File handles | `name_to_handle_at`, `open_by_handle_at`, `openat2`, `close_range` |
| Async I/O | `io_setup`, `io_destroy`, `io_submit`, `io_cancel`, `io_getevents`, `io_pgetevents`, `io_uring_setup`, `io_uring_enter`, `io_uring_register` |
| IPC | `mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr`, `msgget`, `msgctl`, `msgrcv`, `msgsnd`, `semget`, `semctl`, `semtimedop`, `semop`, `shmget`, `shmctl`, `shmat`, `shmdt` |
| Extended attributes | `setxattr`, `lsetxattr`, `fsetxattr`, `getxattr`, `lgetxattr`, `fgetxattr`, `listxattr`, `llistxattr`, `flistxattr`, `removexattr`, `lremovexattr`, `fremovexattr`, `setxattrat`, `getxattrat`, `listxattrat`, `removexattrat` |
| Scheduling | `sched_setparam`, `sched_setscheduler`, `sched_getscheduler`, `sched_getparam`, `sched_setaffinity`, `sched_getaffinity`, `sched_yield`, `sched_get_priority_max`, `sched_get_priority_min`, `sched_rr_get_interval`, `sched_setattr`, `sched_getattr` |
| Capabilities | `capget`, `capset` |
| Mount/namespace | `mount_setattr`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `open_tree`, `open_tree_attr`, `statmount`, `listmount` |
| Security | `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`, `lsm_get_self_attr`, `lsm_set_self_attr`, `lsm_list_modules` |
| Keys | `add_key`, `request_key`, `keyctl` |
| Inotify/fanotify | `inotify_init1`, `inotify_add_watch`, `inotify_rm_watch`, `fanotify_init`, `fanotify_mark` |
| I/O priority | `ioprio_set`, `ioprio_get` |
| Swap | `swapon`, `swapoff` |
| Misc | `nfsservctl`, `quotactl`, `quotactl_fd`, `lookup_dcookie`, `perf_event_open`, `get_robust_list`, `file_getattr`, `file_setattr` |

</details>

## Development Guide

#### Zig
bVisor is written in Zig. Zig is pre-1.0, so compilation is only guaranteed with the exact zig build. We're using a tagged commit on 0.16 dev, which includes major breaking changes (Io) compared to previous versions, so please use the exact version specified in the `build.zig.zon` file. [anyzig](https://github.com/marler8997/anyzig) is the recommended tool for getting the correct version of Zig. It's also recommended to compile ZLS from source using a tagged commit compatible with Zig. You'll be flying blind otherwise.

#### Cross-compilation
bVisor depends on Linux kernel features, although it's developed primarily on ARM Macs. Zig cross-compiles to Linux, and all tests run in Docker.

```bash
zig build           # Cross-compile for all targets (exe, tests, N-API .node binaries)
zig build test      # Unit tests in Docker container
zig build run       # E2E smoke test in Docker (scorecard of supported syscalls)
zig build run-node  # Run E2E node SDK tests with current zig core build
```

`run` and `run-node` support the `-Dfail-loudly` cli flag, to crash on unsupported syscall.
```bash
zig build run -Dfail-loudly
zig build run-node -Dfail-loudly
```
