const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: Proc.SupervisorPID = @intCast(notif.pid);

    const proc = supervisor.guest_procs.get(caller_pid) catch |err| {
        // getpid() never fails in the kernel - if we can't find the process,
        // it's a supervisor invariant violation
        std.debug.panic("getpid: supervisor invariant violated - kernel pid {d} not in guest_procs: {}", .{ caller_pid, err });
    };

    return replySuccess(notif.id, @intCast(proc.pid));
}

test "getpid returns kernel pid" {
    const allocator = testing.allocator;
    const supervisor_pid: Proc.SupervisorPID = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, supervisor_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.getpid, .{ .pid = supervisor_pid });
    const resp = handle(notif, &supervisor);
    try testing.expectEqual(supervisor_pid, resp.val);
}

test "getpid for child process returns child kernel pid" {
    const allocator = testing.allocator;
    const init_pid: Proc.SupervisorPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Add a child process
    const guest_pid: Proc.SupervisorPID = 200;
    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, guest_pid, Procs.CloneFlags.from(0));

    // Child calls getpid
    const notif = makeNotif(.getpid, .{ .pid = guest_pid });
    const resp = handle(notif, &supervisor);
    try testing.expectEqual(guest_pid, resp.val);
}
