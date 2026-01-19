const std = @import("std");
const linux = std.os.linux;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

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

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    // Store clone flags for later retrieval when child is discovered.
    // Child will be lazily registered when it makes its first syscall
    // (or when parent tries to interact with it).
    try supervisor.virtual_procs.pending_clones.append(self.parent_pid, self.clone_flags);

    // Let the kernel execute the clone syscall.
    // Parent will receive the real kernel PID of the child.
    return .use_kernel;
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

test "handle stores flags and returns use_kernel" {
    const allocator = testing.allocator;

    // Setup: create supervisor with initial process
    const initial_pid = 100;
    var supervisor = try Supervisor.init(allocator, -1, initial_pid);
    defer supervisor.deinit();

    // Create clone handler for guest pid 100
    const handler = Self{
        .parent_pid = initial_pid,
        .clone_flags = Procs.CloneFlags.from(linux.CLONE.NEWPID),
    };

    // Execute handle
    const result = try handler.handle(&supervisor);

    // Should return use_kernel
    try testing.expect(result == .use_kernel);

    // Clone flags should be stored in pending_clones
    const flags = supervisor.virtual_procs.pending_clones.remove(initial_pid);
    try testing.expect(flags != null);
    try testing.expect(flags.?.create_pid_namespace());
}
