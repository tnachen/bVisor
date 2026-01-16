const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

/// Smoke test for bVisor sandbox.
/// Exercises clone and openat syscalls to verify PID virtualization.
///
/// Expected behavior when run inside the sandbox:
/// - Initial process has vpid 1
/// - First fork returns vpid 2 to parent (virtualized from kernel PID)
/// - Child process has vpid 2
///
/// Run with: docker run --rm --cap-add=SYS_PTRACE -v ./zig-out:/zig-out alpine /zig-out/bin/bVisor
pub fn smoke_test(_: std.Io) void {
    std.debug.print("\n=== bVisor Smoke Test ===\n\n", .{});

    // Test 1: Fork and verify virtual PID
    test_clone_returns_virtual_pid();

    // Test 2: Nested fork
    test_nested_clone();

    std.debug.print("\n=== All smoke tests passed! ===\n", .{});
}

fn test_clone_returns_virtual_pid() void {
    std.debug.print("Test 1: Clone returns virtual PID\n", .{});

    const fork_result = posix.fork() catch |err| {
        std.debug.panic("Fork failed: {}\n", .{err});
    };

    if (fork_result == 0) {
        // Child process
        std.debug.print("  [child] I am the child process\n", .{});

        // Child should see itself with a virtual PID
        // When we have read() handler, we could verify /proc/self returns vpid 2
        std.debug.print("  [child] Exiting successfully\n", .{});
        linux.exit(0);
    } else {
        // Parent process
        const child_vpid = fork_result;
        std.debug.print("  [parent] Fork returned child vpid: {d}\n", .{child_vpid});

        // In the sandbox, fork should return virtual PID 2 (first child)
        // The ptrace handler should have modified the return value
        if (child_vpid != 2) {
            std.debug.panic("  [parent] FAILED: Expected vpid 2, got {d}\n", .{child_vpid});
        }
        std.debug.print("  [parent] SUCCESS: Got expected virtual PID 2\n", .{});
    }

    std.debug.print("Test 1: PASSED\n\n", .{});
}

fn test_nested_clone() void {
    std.debug.print("Test 2: Nested clone\n", .{});

    const fork1_result = posix.fork() catch |err| {
        std.debug.panic("First fork failed: {}\n", .{err});
    };

    if (fork1_result == 0) {
        // First child (should be vpid 3 after test1)
        std.debug.print("  [child1] I am child 1\n", .{});

        const fork2_result = posix.fork() catch |err| {
            std.debug.panic("Nested fork failed: {}\n", .{err});
        };

        if (fork2_result == 0) {
            // Grandchild (should be vpid 4)
            std.debug.print("  [child2] I am child 2 (grandchild)\n", .{});
            std.debug.print("  [child2] Exiting\n", .{});
            linux.exit(0);
        } else {
            std.debug.print("  [child1] Forked grandchild with vpid: {d}\n", .{fork2_result});
            linux.exit(0);
        }
    } else {
        std.debug.print("  [parent] Forked child 1 with vpid: {d}\n", .{fork1_result});
        linux.exit(0);
    }

    std.debug.print("Test 2: PASSED\n\n", .{});
}
