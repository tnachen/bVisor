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
    return Result.reply_success(@intCast(proc.vpid));
}

test "getpid returns virtual pid" {
    const allocator = testing.allocator;
    const kernel_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, -1, kernel_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.getpid, .{ .pid = kernel_pid });
    const parsed = Self.parse(notif);

    try testing.expectEqual(kernel_pid, parsed.kernel_pid);

    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .reply);
    try testing.expect(!res.is_error());
    // Initial process gets vpid 1
    try testing.expectEqual(@as(i64, 1), res.reply.val);
}

test "getpid for child process returns vpid 2" {
    const allocator = testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, init_pid);
    defer supervisor.deinit();

    // Add a child process
    const child_pid: Proc.KernelPID = 200;
    const child_vpid = try supervisor.virtual_procs.handle_clone(init_pid, child_pid, Procs.CloneFlags.from(0));
    try testing.expectEqual(@as(Procs.VirtualPID, 2), child_vpid);

    // Child calls getpid
    const notif = makeNotif(.getpid, .{ .pid = child_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(!res.is_error());
    try testing.expectEqual(@as(i64, 2), res.reply.val);
}

test "getpid for unknown pid returns ESRCH" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.getpid, .{ .pid = 999 });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(res.is_error());
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.SRCH)), res.reply.errno);
}
