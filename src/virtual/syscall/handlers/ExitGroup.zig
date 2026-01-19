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
    // Clean up virtual proc entry before kernel handles the exit
    // Ignore errors - process may have already been cleaned up
    supervisor.virtual_procs.handle_process_exit(self.kernel_pid) catch {};

    // Let kernel execute the actual exit_group syscall
    return .use_kernel;
}

test "exit_group cleans up proc and returns use_kernel" {
    const allocator = testing.allocator;
    const kernel_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, -1, kernel_pid);
    defer supervisor.deinit();

    // Verify proc exists
    try testing.expect(supervisor.virtual_procs.lookup.get(kernel_pid) != null);

    const notif = makeNotif(.exit_group, .{ .pid = kernel_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    // Should return use_kernel to let kernel handle the actual exit
    try testing.expect(res == .use_kernel);

    // Proc should be cleaned up
    try testing.expectEqual(@as(?*Proc, null), supervisor.virtual_procs.lookup.get(kernel_pid));
}

test "exit_group cleans up child process tree" {
    const allocator = testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, init_pid);
    defer supervisor.deinit();

    // Create: init(100) -> child(200) -> grandchild(300)
    const child_pid: Proc.KernelPID = 200;
    const parent = supervisor.virtual_procs.lookup.get(init_pid).?;
    _ = try supervisor.virtual_procs.register_child(parent, child_pid, Procs.CloneFlags.from(0));

    const grandchild_pid: Proc.KernelPID = 300;
    const child = supervisor.virtual_procs.lookup.get(child_pid).?;
    _ = try supervisor.virtual_procs.register_child(child, grandchild_pid, Procs.CloneFlags.from(0));

    try testing.expectEqual(@as(usize, 3), supervisor.virtual_procs.lookup.size);

    // Child exits - should also clean up grandchild
    const notif = makeNotif(.exit_group, .{ .pid = child_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(res == .use_kernel);

    // Child and grandchild should be cleaned up, init should remain
    try testing.expectEqual(@as(usize, 1), supervisor.virtual_procs.lookup.size);
    try testing.expect(supervisor.virtual_procs.lookup.get(init_pid) != null);
    try testing.expectEqual(@as(?*Proc, null), supervisor.virtual_procs.lookup.get(child_pid));
    try testing.expectEqual(@as(?*Proc, null), supervisor.virtual_procs.lookup.get(grandchild_pid));
}

test "exit_group for unknown pid is no-op" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.exit_group, .{ .pid = 999 });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    // Should still return use_kernel
    try testing.expect(res == .use_kernel);

    // Original proc should still exist
    try testing.expectEqual(@as(usize, 1), supervisor.virtual_procs.lookup.size);
}
