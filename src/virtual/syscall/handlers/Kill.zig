const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

const Self = @This();

kernel_pid: Proc.KernelPID, // caller's kernel pid
target_vpid: Procs.VirtualPID, // arg0 (pid_t pid)
signal: u6, // arg1 (int sig) - stored as raw value for cross-platform

pub fn parse(notif: linux.SECCOMP.notif) Self {
    return .{
        .kernel_pid = @intCast(notif.pid),
        .target_vpid = @intCast(@as(i64, @bitCast(notif.data.arg0))),
        .signal = @truncate(notif.data.arg1),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    // Negative PIDs (process groups) not supported
    if (self.target_vpid <= 0) {
        return Result.reply_err(.NOSYS);
    }

    // Get caller's process and namespace
    const proc = supervisor.virtual_procs.procs.get(self.kernel_pid) orelse
        return Result.reply_err(.SRCH);

    // Translate vpid to kernel pid within caller's namespace
    const target_proc = proc.namespace.get_proc(self.target_vpid) orelse
        return Result.reply_err(.SRCH);

    // Execute real kill syscall
    const sig: posix.SIG = @enumFromInt(self.signal);
    posix.kill(@intCast(target_proc.pid), sig) catch |err| {
        const errno: linux.E = switch (err) {
            error.PermissionDenied => .PERM,
            error.ProcessNotFound => .SRCH,
            else => .INVAL,
        };
        return Result.reply_err(errno);
    };

    return Result.reply_success(0);
}

test "parse extracts target vpid and signal" {
    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = 5, // target vpid
        .arg1 = 9, // SIGKILL
    });

    const parsed = Self.parse(notif);
    try testing.expectEqual(@as(Proc.KernelPID, 100), parsed.kernel_pid);
    try testing.expectEqual(@as(Procs.VirtualPID, 5), parsed.target_vpid);
    try testing.expectEqual(@as(u6, 9), parsed.signal);
}

test "kill with negative pid returns ENOSYS" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = @as(u64, @bitCast(@as(i64, -1))), // -1 = all processes
        .arg1 = 9,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(res.is_error());
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.NOSYS)), res.reply.errno);
}

test "kill with zero pid returns ENOSYS" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = 0, // process group
        .arg1 = 9,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(res.is_error());
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.NOSYS)), res.reply.errno);
}

test "kill from unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 999, // unknown caller
        .arg0 = 1,
        .arg1 = 9,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(res.is_error());
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.SRCH)), res.reply.errno);
}

test "kill with unknown target vpid returns ESRCH" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = 999, // unknown target
        .arg1 = 9,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(res.is_error());
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.SRCH)), res.reply.errno);
}
