const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const isError = @import("../../../seccomp/notif.zig").isError;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: Proc.SupervisorPID = @intCast(notif.pid);

    const proc = supervisor.guest_procs.get(caller_pid) catch |err| {
        // getppid() never fails in the kernel - if we can't find the process,
        // it's a supervisor invariant violation
        std.debug.panic("getppid: supervisor invariant violated - kernel pid {d} not in guest_procs: {}", .{ caller_pid, err });
    };

    // Return parent's kernel PID, or 0 if:
    // - No parent (sandbox root)
    // - Parent not visible (e.g., in CLONE_NEWPID case where parent is in different namespace)
    const ppid: Proc.SupervisorPID = if (proc.parent) |p|
        if (proc.canSee(p)) p.pid else 0
    else
        0;

    return replySuccess(notif.id, @intCast(ppid));
}

test "getppid for init process returns 0" {
    const allocator = testing.allocator;
    const supervisor_pid: Proc.SupervisorPID = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, supervisor_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.getppid, .{ .pid = supervisor_pid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "getppid for child process returns parent kernel pid" {
    const allocator = testing.allocator;
    const init_pid: Proc.SupervisorPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Add a child process
    const guest_pid: Proc.SupervisorPID = 200;
    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, guest_pid, Procs.CloneFlags.from(0));

    // Child calls getppid
    const notif = makeNotif(.getppid, .{ .pid = guest_pid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    // Parent kernel PID
    try testing.expectEqual(@as(i64, init_pid), resp.val);
}

test "getppid for grandchild returns parent kernel pid" {
    const allocator = testing.allocator;
    const init_pid: Proc.SupervisorPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Create: init(100) -> child(200) -> grandchild(300)
    const guest_pid: Proc.SupervisorPID = 200;
    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, guest_pid, Procs.CloneFlags.from(0));

    const grandguest_pid: Proc.SupervisorPID = 300;
    const child = supervisor.guest_procs.lookup.get(guest_pid).?;
    _ = try supervisor.guest_procs.registerChild(child, grandguest_pid, Procs.CloneFlags.from(0));

    // Grandchild calls getppid
    const notif = makeNotif(.getppid, .{ .pid = grandguest_pid });
    const resp = handle(notif, &supervisor);

    try testing.expect(!isError(resp));
    // Parent (child) kernel PID
    try testing.expectEqual(@as(i64, guest_pid), resp.val);
}

test "getppid for CLONE_NEWPID child returns 0" {
    const allocator = testing.allocator;
    const init_pid: Proc.SupervisorPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Child in new namespace
    const guest_pid: Proc.SupervisorPID = 200;
    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, guest_pid, Procs.CloneFlags.from(linux.CLONE.NEWPID));

    // Child calls getppid - parent is not visible in child's namespace
    const notif = makeNotif(.getppid, .{ .pid = guest_pid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    // Parent not visible, returns 0
    try testing.expectEqual(@as(i64, 0), resp.val);
}
