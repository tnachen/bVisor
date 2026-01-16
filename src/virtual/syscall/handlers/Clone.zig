const std = @import("std");
const linux = std.os.linux;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const deps = @import("../../../deps/deps.zig");
const ptrace = deps.ptrace;

const Self = @This();

parent_pid: Proc.KernelPID,
clone_flags: Procs.CloneFlags,

pub fn parse(notif: linux.SECCOMP.notif) !Self {
    // clone(flags, stack, parent_tid, child_tid, tls)
    // arg0 = flags on aarch64
    return .{
        .parent_pid = @intCast(notif.pid),
        .clone_flags = Procs.CloneFlags.from(notif.data.arg0),
    };
}

pub fn handle(self: Self, _: *Supervisor) !Result {
    // Clone is a special case:
    // - The syscall must execute in the kernel (supervisor can't invoke it)
    // - We need to intercept the result to virtualize the child PID
    // - Seccomp only intercepts BEFORE syscalls, not after
    // - Solution: use ptrace with TRACECLONE to catch clone completion

    // Attach ptrace while guest (parent) is seccomp-stopped
    // TRACECLONE will cause the guest to stop after clone returns
    try ptrace.seize_for_clone(self.parent_pid);

    // Let the kernel execute the clone syscall
    // We'll intercept the result in handle_exit
    return .use_kernel;
}

pub fn handle_exit(self: Self, supervisor: *Supervisor) !void {
    // Once fully handled, detach ptrace from parent process so it can continue normally
    defer ptrace.detach(self.parent_pid) catch {};

    // Wait for PTRACE_EVENT_CLONE, then continue to syscall-exit where we can modify x0
    const child_kernel_pid = try ptrace.wait_clone_event(self.parent_pid);

    // Child process has ptrace automatically attached on it, detach so it can continue normally
    defer ptrace.detach_child(child_kernel_pid) catch {};

    // Register new child in virtual proc system
    const child_vpid = try supervisor.virtual_procs.handle_clone(
        self.parent_pid,
        child_kernel_pid,
        self.clone_flags,
    );

    // Modify return value to parent to be the virtual PID of child
    try ptrace.set_return_value(self.parent_pid, @intCast(child_vpid));
}

test "parse extracts clone flags" {
    const notif = makeNotif(.clone, .{
        .pid = 100,
        .arg0 = linux.CLONE.NEWPID | linux.CLONE.FILES,
    });

    const parsed = try Self.parse(notif);
    try testing.expectEqual(@as(Proc.KernelPID, 100), parsed.parent_pid);
    try testing.expect(parsed.clone_flags.create_pid_namespace());
    try testing.expect(parsed.clone_flags.share_files());
}

test "handle_exit registers child and modifies return value" {
    const allocator = testing.allocator;

    // Setup: create supervisor with initial process
    const initial_pid = 100;
    var supervisor = try Supervisor.init(allocator, -1, initial_pid);
    defer supervisor.deinit();

    // Configure ptrace mock to return child PID 200
    ptrace.testing.setup_clone_result(200);

    // Create clone handler for guest pid 100
    const handler = Self{
        .parent_pid = initial_pid,
        .clone_flags = Procs.CloneFlags.from(0), // no special flags
    };

    // Execute handle_exit
    try handler.handle_exit(&supervisor);

    // Verify child was registered
    const child_proc = supervisor.virtual_procs.procs.get(200);
    try testing.expect(child_proc != null);
    try testing.expectEqual(@as(Procs.VirtualPID, 2), child_proc.?.vpid);

    // Verify return value was modified to virtual PID
    try testing.expectEqual(@as(i64, 2), ptrace.testing.test_modified_return.?);

    // Verify detach was called
    try testing.expect(ptrace.testing.test_detach_called);
    try testing.expect(ptrace.testing.test_child_detach_called);
}

test "handle_exit with CLONE_NEWPID creates new namespace" {
    const allocator = testing.allocator;

    const initial_pid = 100;
    var supervisor = try Supervisor.init(allocator, -1, initial_pid);
    defer supervisor.deinit();

    ptrace.testing.setup_clone_result(200);

    const handler = Self{
        .parent_pid = initial_pid,
        .clone_flags = Procs.CloneFlags.from(linux.CLONE.NEWPID),
    };

    try handler.handle_exit(&supervisor);

    // Child should be in a new namespace with vpid 1
    const child_proc = supervisor.virtual_procs.procs.get(200);
    try testing.expect(child_proc != null);
    try testing.expectEqual(@as(Procs.VirtualPID, 1), child_proc.?.vpid);
    try testing.expect(child_proc.?.is_namespace_root());

    // Return value should be virtual PID 1
    try testing.expectEqual(@as(i64, 1), ptrace.testing.test_modified_return.?);
}
