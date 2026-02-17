const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const Supervisor = @import("../../../Supervisor.zig");
const Symlinks = @import("../../Symlinks.zig");
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    // Handling execve is tricky. Similarly to clone, must be called by guest process.
    // To redirect exec to a sandboxed file, we overwrite the path in guest memory before replyContinue.
    // Sandboxed filesystem lives at `/tmp/.bvisor/ ...`.
    // For COW/TMP files, the real overlay path is longer than the guest's buffer, so we create
    // a short symlink at /.b/XXX that points to the overlay path and write that into guest memory

    const logger = supervisor.logger;
    const caller_tid: AbsTid = @intCast(notif.pid);

    // Read pathname from child memory (arg0 is pointer to path)
    const path_ptr: u64 = notif.data.arg0;
    var path_buf: [256]u8 = undefined;
    const path = try memory_bridge.readString(&path_buf, caller_tid, path_ptr);
    if (path.len == 0) {
        return LinuxErr.INVAL;
    }

    // Resolve against cwd
    var cwd_buf: [512]u8 = undefined;
    const cwd: []const u8 = blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);
        const c = caller.fs_info.cwd;
        if (c.len > cwd_buf.len) return LinuxErr.NAMETOOLONG;
        @memcpy(cwd_buf[0..c.len], c);
        break :blk cwd_buf[0..c.len];
    };

    var resolve_buf: [512]u8 = undefined;
    const route_result = resolveAndRoute(cwd, path, &resolve_buf) catch {
        return LinuxErr.NAMETOOLONG;
    };

    switch (route_result) {
        .block => {
            logger.log("execve: blocked path: {s}", .{path});
            return LinuxErr.PERM;
        },
        .handle => |h| {
            switch (h.backend) {
                .proc => {
                    logger.log("execve: cannot exec proc file: {s}", .{path});
                    return LinuxErr.ACCES;
                },
                .passthrough => {
                    // Guest's presumed path maps directly to the actual kernel path
                    logger.log("execve: passthrough {s}", .{h.normalized});
                    return replyContinue(notif.id);
                },
                .cow => {
                    // If guest's presumed path maps to a COW copy:
                    if (supervisor.overlay.cowExists(h.normalized)) {
                        var cow_path_buf: [512]u8 = undefined;
                        const cow_path = try supervisor.overlay.resolveCow(h.normalized, &cow_path_buf);
                        return execViaSymlink(supervisor, notif.id, cow_path, path.len, caller_tid, path_ptr);
                    }
                    // No COW copy exists; the original kernel path is correct
                    return replyContinue(notif.id);
                },
                .tmp => {
                    var tmp_path_buf: [512]u8 = undefined;
                    const tmp_path = try supervisor.overlay.resolveTmp(h.normalized, &tmp_path_buf);
                    return execViaSymlink(supervisor, notif.id, tmp_path, path.len, caller_tid, path_ptr);
                },
            }
        },
    }
}

/// Create a short symlink pointing to `kernel_path`, write it into the guest's memory, and replyContinue.
fn execViaSymlink(
    supervisor: *Supervisor,
    notif_id: u64,
    kernel_path: []const u8,
    original_path_len: usize,
    caller_tid: AbsTid,
    path_ptr: u64,
) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    var symlink_buf: [Symlinks.path_len + 1]u8 = undefined;
    const symlink_path = supervisor.symlinks.create(kernel_path, original_path_len, &symlink_buf) catch |err| {
        logger.log("execve: symlink creation failed: {s}", .{@errorName(err)});
        return LinuxErr.PERM;
    };

    logger.log("execve: symlink {s} -> {s}", .{ symlink_path, kernel_path });
    try memory_bridge.writeString(symlink_path, caller_tid, path_ptr);

    const resp = replyContinue(notif_id);

    _ = linux.unlinkat(linux.AT.FDCWD, symlink_buf[0..Symlinks.path_len :0], 0);

    return resp;
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

fn makeExecveNotif(pid: AbsTid, path: [*:0]const u8) linux.SECCOMP.notif {
    return makeNotif(.execve, .{
        .pid = pid,
        .arg0 = @intFromPtr(path),
    });
}

test "execve /bin/sh returns CONTINUE" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(init_tid, "/bin/sh");
    const resp = try handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "execve /sys/blocked returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(init_tid, "/sys/something");
    try testing.expectError(error.PERM, handle(notif, &supervisor));
}

test "execve /proc/self returns EACCES" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(init_tid, "/proc/self");
    try testing.expectError(error.ACCES, handle(notif, &supervisor));
}

test "execve empty path returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(init_tid, "");
    try testing.expectError(error.INVAL, handle(notif, &supervisor));
}

test "execve unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(999, "/bin/sh");
    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}
