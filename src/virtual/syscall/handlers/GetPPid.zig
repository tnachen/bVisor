const std = @import("std");
const linux = std.os.linux;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

const Self = @This();

kernel_pid: Proc.KernelPID,

pub fn parse(notif: linux.SECCOMP.notif) Self {
    return .{ .kernel_pid = @intCast(notif.pid) };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const proc = supervisor.virtual_procs.procs.get(self.kernel_pid) orelse
        return Result.reply_err(.SRCH);
    const ppid: Procs.VirtualPID = if (proc.parent) |p| p.vpid else 0;
    return Result.reply_success(@intCast(ppid));
}

test "getppid for init process returns 0" {
    const allocator = testing.allocator;
    const kernel_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, -1, kernel_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.getppid, .{ .pid = kernel_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(!res.is_error());
    try testing.expectEqual(@as(i64, 0), res.reply.val);
}

test "getppid for child process returns parent vpid" {
    const allocator = testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, init_pid);
    defer supervisor.deinit();

    // Add a child process
    const child_pid: Proc.KernelPID = 200;
    _ = try supervisor.virtual_procs.handle_clone(init_pid, child_pid, Procs.CloneFlags.from(0));

    // Child calls getppid
    const notif = makeNotif(.getppid, .{ .pid = child_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(!res.is_error());
    // Parent (init) has vpid 1
    try testing.expectEqual(@as(i64, 1), res.reply.val);
}

test "getppid for grandchild returns parent vpid" {
    const allocator = testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, init_pid);
    defer supervisor.deinit();

    // Create: init(1) -> child(2) -> grandchild(3)
    const child_pid: Proc.KernelPID = 200;
    _ = try supervisor.virtual_procs.handle_clone(init_pid, child_pid, Procs.CloneFlags.from(0));

    const grandchild_pid: Proc.KernelPID = 300;
    _ = try supervisor.virtual_procs.handle_clone(child_pid, grandchild_pid, Procs.CloneFlags.from(0));

    // Grandchild calls getppid
    const notif = makeNotif(.getppid, .{ .pid = grandchild_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(!res.is_error());
    // Parent (child) has vpid 2
    try testing.expectEqual(@as(i64, 2), res.reply.val);
}

test "getppid for unknown pid returns ESRCH" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.getppid, .{ .pid = 999 });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(res.is_error());
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.SRCH)), res.reply.errno);
}
