const std = @import("std");
const linux = std.os.linux;

/// Test state for simulating ptrace behavior
pub var test_child_pid: ?linux.pid_t = null;
pub var test_modified_return: ?i64 = null;
pub var test_seize_called: bool = false;
pub var test_detach_called: bool = false;
pub var test_child_detach_called: bool = false;

/// Reset all test state
pub fn reset() void {
    test_child_pid = null;
    test_modified_return = null;
    test_seize_called = false;
    test_detach_called = false;
    test_child_detach_called = false;
}

/// Configure the mock to return a specific child PID from wait_clone_event
pub fn setup_clone_result(child_pid: linux.pid_t) void {
    reset();
    test_child_pid = child_pid;
}

/// Mock: Attach ptrace for clone tracking
pub fn seize_for_clone(_: linux.pid_t) !void {
    test_seize_called = true;
}

/// Mock: Wait for clone event and return the configured child PID
pub fn wait_clone_event(_: linux.pid_t) !linux.pid_t {
    return test_child_pid orelse return error.TestNotConfigured;
}

/// Mock: Record the return value that would be set
pub fn set_return_value(_: linux.pid_t, value: i64) !void {
    test_modified_return = value;
}

/// Mock: Detach from guest process
pub fn detach(_: linux.pid_t) !void {
    test_detach_called = true;
}

/// Mock: Detach from auto-traced child
pub fn detach_child(_: linux.pid_t) !void {
    test_child_detach_called = true;
}
