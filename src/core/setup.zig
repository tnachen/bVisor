const std = @import("std");
const linux = std.os.linux;
const types = @import("types.zig");
const seccomp = @import("seccomp/filter.zig");
const Logger = types.Logger;
const Supervisor = @import("Supervisor.zig");
const LogBuffer = @import("LogBuffer.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const pidfd = @import("utils/pidfd.zig");
const lookupGuestFd = pidfd.lookupGuestFdWithRetry;

/// The guest calls close_range(3, MAX) then seccomp.install(), so the
/// notify FD is always 3 (the first slot after stdio)
const expected_notify_fd: linux.fd_t = 3;

pub fn execute(allocator: Allocator, io: Io, uid: [16]u8, cmd: [:0]const u8, stdout: *LogBuffer, stderr: *LogBuffer) !void {
    const start_time = Io.Clock.awake.now(io);

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) return error.SyscallFailed;
    const fork_result: linux.pid_t = @intCast(fork_rc);
    if (fork_result == 0) {
        guestProcess(cmd);
    } else {
        const init_guest_tid: linux.pid_t = fork_result;
        try supervisorProcess(
            allocator,
            io,
            uid,
            start_time,
            init_guest_tid,
            stdout,
            stderr,
        );
    }
}

fn guestProcess(cmd: [:0]const u8) noreturn {
    // Close all inherited FDs except stdio (0/1/2) so the guest starts
    // with a clean kernel FD table. seccomp.install() will then allocate
    // the notify FD at slot 3 (the first available)
    _ = linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = false });

    // Install seccomp filter — notify FD lands at slot 3
    const notify_fd = seccomp.install() catch {
        linux.exit_group(1);
    };
    if (notify_fd != expected_notify_fd) {
        linux.exit_group(1);
    }
    // Note all syscalls after this point will be handled by supervisor

    // Execve into a bash command
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", cmd.ptr };
    // TODO: expose environment variables
    const envp = [_:null]?[*:0]const u8{
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/",
    };

    _ = linux.execve("/bin/sh", &argv, &envp);
    linux.exit_group(1); // only reached if execve fails
}

fn supervisorProcess(
    allocator: Allocator,
    io: Io,
    uid: [16]u8,
    start_time: Io.Timestamp,
    init_guest_tid: linux.pid_t,
    stdout: *LogBuffer,
    stderr: *LogBuffer,
) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Supervisor process starting", .{});
    defer logger.log("Supervisor process exiting", .{});

    const notify_fd = try lookupGuestFd(init_guest_tid, expected_notify_fd, io);

    var supervisor = try Supervisor.init(allocator, io, uid, notify_fd, init_guest_tid, stdout, stderr);
    defer supervisor.deinit();
    const now = Io.Clock.awake.now(io);
    const duration = now.durationTo(start_time);
    logger.log("Supervisor process  {d}ms", .{duration.toMilliseconds()});
    try supervisor.run();
}

pub fn generateUid(io: Io) [16]u8 {
    var uid_bytes: [8]u8 = undefined;
    io.random(&uid_bytes);
    return std.fmt.bytesToHex(uid_bytes, .lower);
}
