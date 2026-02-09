const napi = @import("napi.zig");
const c = napi.c;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const core = @import("core");
const Supervisor = core.Supervisor;
const smokeTest = core.smokeTest;
const seccomp = core.seccomp;
const lookupGuestFd = core.lookupGuestFdWithRetry;
const Logger = core.Logger;

const Self = @This();

active_supervisor: ?Supervisor = null,

// Lifecycle helpers expect init/deinit
pub fn init(allocator: std.mem.Allocator) !*Self {
    const self = try allocator.create(Self);
    self.* = .{};
    return self;
}

pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    allocator.destroy(self);
}

fn supervisorProcess(self: *Self, init_guest_tid: linux.pid_t, expected_notify_fd: linux.fd_t) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Supervisor process starting", .{});
    defer logger.log("Supervisor process exiting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const notify_fd = try lookupGuestFd(init_guest_tid, expected_notify_fd, io);

    var supervisor = try Supervisor.init(gpa, io, notify_fd, init_guest_tid);
    defer supervisor.deinit();
    self.active_supervisor = supervisor;
    try supervisor.run();
}

fn guestProcess(expected_notify_fd: linux.fd_t) !void {
    const notify_fd = try seccomp.install();
    if (notify_fd != expected_notify_fd) {
        return error.NotifyFdMismatch;
    }
    @call(.never_inline, smokeTest, .{});
    linux.exit(0);
}

// Public API must follow napi interface
// Returns JS type (RunCmdResult)
pub fn runCmd(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
    const self = napi.ZigExternal(Self).unwrap(env, info) catch return null;

    // Probe the next available FD: dup gives the lowest free FD, then close it.
    // After fork, seccomp.install() in the child will allocate the same FD number.
    const expected_notify_fd = posix.dup(0) catch |err| {
        std.log.err("dup probe failed: {s}", .{@errorName(err)});
        return null;
    };
    posix.close(expected_notify_fd);

    // Setup supervisor and smoke test guest process
    const fork_result = posix.fork() catch |err| {
        std.log.err("Fork failed: {s}", .{@errorName(err)});
        linux.exit(1);
    };
    if (fork_result == 0) {
        guestProcess(expected_notify_fd) catch |err| {
            std.log.err("Guest process failed: {s}", .{@errorName(err)});
            linux.exit(1);
        };
        unreachable; // Guest process is responsible for exiting
    } else {
        const init_guest_tid: linux.pid_t = fork_result;
        supervisorProcess(self, init_guest_tid, expected_notify_fd) catch |err| {
            std.log.err("Supervisor process failed: {s}", .{@errorName(err)});
            linux.exit(1);
        };
        // runs until complete
    }

    // TODO: actually run command
    var stdout: ?*Stream = Stream.init(napi.allocator) catch return null;
    errdefer if (stdout) |s| s.deinit(napi.allocator);
    var stderr: ?*Stream = Stream.init(napi.allocator) catch return null;
    errdefer if (stderr) |s| s.deinit(napi.allocator);

    // Wrap into externals - after wrap(), JS owns the memory via GC finalizer
    const stdoutExternal = napi.ZigExternal(Stream).wrap(env, stdout.?) catch return null;
    stdout = null; // Transfer ownership to JS, effectively cancelling errdefer
    const stderrExternal = napi.ZigExternal(Stream).wrap(env, stderr.?) catch return null;
    stderr = null; // Transfer ownership to JS, effectively cancelling errdefer

    // Create object to return
    const result = napi.createObject(env) catch return null;
    if (result == null) return null;

    // Register externals as properties on object
    napi.setProperty(env, result, "stdout", stdoutExternal) catch return null;
    napi.setProperty(env, result, "stderr", stderrExternal) catch return null;

    return result;
}

pub const Stream = struct {
    content: []const u8 = "a b c d e f g h i j k l m n o p q r s t u v w x y z",
    cursor: usize = 0,

    pub fn init(allocator: std.mem.Allocator) !*Stream {
        const self = try allocator.create(Stream);
        self.* = .{};
        return self;
    }

    pub fn deinit(self: *Stream, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }

    /// Returns JS type (Uint8array | none)
    pub fn next(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
        const self = napi.ZigExternal(Stream).unwrap(env, info) catch return null;

        if (self.cursor >= self.content.len) return napi.getNull(env) catch return null;

        const chunk = self.content[self.cursor..@min(self.cursor + 5, self.content.len)];
        defer self.cursor += 5;

        if (chunk.len == 0) return napi.getNull(env) catch return null;
        return napi.createUint8Array(env, chunk.ptr, chunk.len) catch return null;
    }
};
