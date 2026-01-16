const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const LinuxResult = @import("../../../types.zig").LinuxResult;

/// aarch64 user registers structure for ptrace GETREGSET/SETREGSET
pub const user_regs_aarch64 = extern struct {
    regs: [31]u64, // x0-x30
    sp: u64,
    pc: u64,
    pstate: u64,
};

/// NT_PRSTATUS for GETREGSET/SETREGSET
pub const NT_PRSTATUS: usize = 1;

/// Attach ptrace to a process for clone event tracking.
/// Uses PTRACE_SEIZE with TRACECLONE/TRACEFORK/TRACEVFORK options.
/// The process is already stopped by seccomp, so we don't need to stop it again.
pub fn seize_for_clone(pid: linux.pid_t) !void {
    // Set options to trace clone/fork/vfork events
    // We pass options directly to SEIZE as the 4th argument (data)
    const options = linux.PTRACE.O.TRACECLONE |
        linux.PTRACE.O.TRACEFORK |
        linux.PTRACE.O.TRACEVFORK;

    // PTRACE_SEIZE with options - attaches without stopping
    // The process is already in seccomp-stop, so this should work
    const seize_result = linux.ptrace(
        linux.PTRACE.SEIZE,
        pid,
        0,
        options, // Pass options directly to SEIZE
        0,
    );
    _ = try LinuxResult(usize).from(seize_result).unwrap();
}

/// Wait for a clone/fork/vfork event and return the child's kernel PID.
/// Blocks until the event occurs, then continues to syscall-exit where
/// the return value can be modified.
pub fn wait_clone_event(pid: linux.pid_t) !linux.pid_t {
    // Wait for the process to stop with a clone event
    var status: u32 = 0;
    var wait_result = linux.waitpid(pid, &status, 0);
    _ = try LinuxResult(usize).from(wait_result).unwrap();

    // Check if stopped
    if (!linux.W.IFSTOPPED(status)) {
        return error.ProcessNotStopped;
    }

    // Check for clone/fork/vfork event
    // Event is in bits 16-23 of status: (status >> 16) & 0xff
    const event = (status >> 16) & 0xff;
    if (event != linux.PTRACE.EVENT.CLONE and
        event != linux.PTRACE.EVENT.FORK and
        event != linux.PTRACE.EVENT.VFORK)
    {
        return error.NotCloneEvent;
    }

    // Get the child PID via GETEVENTMSG
    var child_pid: usize = 0;
    const msg_result = linux.ptrace(
        linux.PTRACE.GETEVENTMSG,
        pid,
        0,
        @intFromPtr(&child_pid),
        0,
    );
    _ = try LinuxResult(usize).from(msg_result).unwrap();

    // Continue the tracee to the syscall-exit stop where x0 will have the return value
    const cont_result = linux.ptrace(
        linux.PTRACE.SYSCALL,
        pid,
        0,
        0,
        0,
    );
    _ = try LinuxResult(usize).from(cont_result).unwrap();

    // Wait for syscall-exit stop
    wait_result = linux.waitpid(pid, &status, 0);
    _ = try LinuxResult(usize).from(wait_result).unwrap();

    if (!linux.W.IFSTOPPED(status)) {
        return error.ProcessNotStopped;
    }

    return @intCast(child_pid);
}

/// Modify the return value register (x0 on aarch64) of a stopped process.
pub fn set_return_value(pid: linux.pid_t, value: i64) !void {
    var regs: user_regs_aarch64 = undefined;
    var iov = posix.iovec{
        .base = @ptrCast(&regs),
        .len = @sizeOf(user_regs_aarch64),
    };

    // Get current registers
    const get_result = linux.ptrace(
        linux.PTRACE.GETREGSET,
        pid,
        NT_PRSTATUS,
        @intFromPtr(&iov),
        0,
    );
    _ = try LinuxResult(usize).from(get_result).unwrap();

    // Modify x0 (return value register on aarch64)
    regs.regs[0] = @bitCast(value);

    // Write back registers
    const set_result = linux.ptrace(
        linux.PTRACE.SETREGSET,
        pid,
        NT_PRSTATUS,
        @intFromPtr(&iov),
        0,
    );
    _ = try LinuxResult(usize).from(set_result).unwrap();
}

/// Detach from a traced process, allowing it to continue.
pub fn detach(pid: linux.pid_t) !void {
    const result = linux.ptrace(
        linux.PTRACE.DETACH,
        pid,
        0,
        0,
        0,
    );
    _ = try LinuxResult(usize).from(result).unwrap();
}

/// Detach from the auto-traced child process.
/// The child is in PTRACE_EVENT_STOP state after clone, we need to let it run.
pub fn detach_child(child_pid: linux.pid_t) !void {
    // First wait for the child to be in a stopped state
    var status: u32 = 0;
    const wait_result = linux.waitpid(child_pid, &status, 0);
    _ = try LinuxResult(usize).from(wait_result).unwrap();

    // Now detach
    const result = linux.ptrace(
        linux.PTRACE.DETACH,
        child_pid,
        0,
        0,
        0,
    );
    _ = try LinuxResult(usize).from(result).unwrap();
}
