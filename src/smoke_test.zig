const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

/// Simple linear smoke test for bVisor sandbox.
/// Just cranks through each virtualized syscall to verify they work.
/// Panics on any unexpected behavior.
///
/// Run with: docker run --rm --cap-add=SYS_PTRACE -v ./zig-out:/zig-out alpine /zig-out/bin/bVisor
pub fn smoke_test(_: std.Io) void {
    std.debug.print("\n=== bVisor Smoke Test ===\n\n", .{});

    // 1. getpid - should return vpid 1 for init process
    const my_pid = linux.getpid();
    std.debug.print("getpid() = {d}\n", .{my_pid});
    std.debug.assert(my_pid == 1);

    // 2. getppid - init has no parent, should return 0
    const my_ppid = linux.getppid();
    std.debug.print("getppid() = {d}\n", .{my_ppid});
    std.debug.assert(my_ppid == 0);

    // 3. clone/fork - should return vpid 2
    const fork_result = posix.fork() catch |err| {
        std.debug.panic("fork() failed: {}\n", .{err});
    };

    if (fork_result == 0) {
        // Child process
        const child_pid = linux.getpid();
        std.debug.print("  [child] getpid() = {d}\n", .{child_pid});
        std.debug.assert(child_pid == 2);

        const child_ppid = linux.getppid();
        std.debug.print("  [child] getppid() = {d}\n", .{child_ppid});
        std.debug.assert(child_ppid == 1);

        // exit_group - cleans up and exits
        std.debug.print("  [child] exit_group(0)\n", .{});
        linux.exit_group(0);
    }

    // Parent continues
    std.debug.print("fork() = {d}\n", .{fork_result});
    std.debug.assert(fork_result == 2);

    // 4. kill - send signal 0 to child (just checks if process exists)
    const kill_result = linux.kill(2, @enumFromInt(0));
    const kill_errno = linux.errno(kill_result);
    std.debug.print("kill(2, 0) = {s}\n", .{@tagName(kill_errno)});
    // SUCCESS = child still alive, SRCH = child already exited, both OK
    std.debug.assert(kill_errno == .SUCCESS or kill_errno == .SRCH);

    // 5. openat - open /proc/self/status (virtualized)
    const fd = posix.openat(linux.AT.FDCWD, "/proc/self/status", .{}, 0) catch |err| {
        std.debug.panic("openat(/proc/self/status) failed: {}\n", .{err});
    };
    std.debug.print("openat(/proc/self/status) = {d}\n", .{fd});
    posix.close(fd);

    std.debug.print("\n=== All tests passed ===\n", .{});
}
