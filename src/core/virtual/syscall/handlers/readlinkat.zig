const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const Cow = @import("../../fs/backend/cow.zig").Cow;
const Tmp = @import("../../fs/backend/tmp.zig").Tmp;
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const OverlayRoot = @import("../../OverlayRoot.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: readlinkat(dirfd, pathname, buf, bufsiz)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const dirfd: i32 = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    const pathname_ptr: u64 = notif.data.arg1;
    const buf_ptr: u64 = notif.data.arg2;
    const bufsiz: usize = @intCast(notif.data.arg3);

    // Read the pathname from guest memory
    var path_buf: [256]u8 = undefined;
    const pathname = try memory_bridge.readString(&path_buf, caller_tid, pathname_ptr);

    if (pathname.len == 0) return LinuxErr.NOENT;

    // Resolve base directory for pathname
    var base_buf: [512]u8 = undefined;
    const base: []const u8 = if (pathname[0] == '/') "/" else blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        if (dirfd != linux.AT.FDCWD) {
            const dir_file = caller.fd_table.get_ref(dirfd) orelse {
                logger.log("readlinkat: EBADF for dirfd={d}", .{dirfd});
                return LinuxErr.BADF;
            };
            defer dir_file.unref();

            const dir_path = dir_file.opened_path orelse {
                logger.log("readlinkat: dirfd={d} has no associated path", .{dirfd});
                return LinuxErr.NOTDIR;
            };
            if (dir_path.len > base_buf.len) return LinuxErr.NAMETOOLONG;
            @memcpy(base_buf[0..dir_path.len], dir_path);
            break :blk base_buf[0..dir_path.len];
        }

        const c = caller.fs_info.cwd;
        if (c.len > base_buf.len) return LinuxErr.NAMETOOLONG;
        @memcpy(base_buf[0..c.len], c);
        break :blk base_buf[0..c.len];
    };

    var resolve_buf: [512]u8 = undefined;
    const route_result = resolveAndRoute(base, pathname, &resolve_buf) catch {
        return LinuxErr.NAMETOOLONG;
    };

    switch (route_result) {
        .block => {
            logger.log("readlinkat: blocked path: {s}", .{pathname});
            return LinuxErr.PERM;
        },
        .handle => |h| {
            switch (h.backend) {
                .event => unreachable, // eventfd are not opened via path routing
                .passthrough => return LinuxErr.PERM,
                .cow => {
                    // Check tombstones
                    supervisor.mutex.lockUncancelable(supervisor.io);
                    defer supervisor.mutex.unlock(supervisor.io);
                    if (supervisor.tombstones.isAncestorTombstoned(h.normalized) or
                        supervisor.tombstones.isTombstoned(h.normalized))
                        return LinuxErr.NOENT;

                    // If COW copy exists, readlink from overlay; else from real FS
                    var cow_path_buf: [512]u8 = undefined;
                    const real_path = if (supervisor.overlay.cowExists(h.normalized))
                        try supervisor.overlay.resolveCow(h.normalized, &cow_path_buf)
                    else
                        h.normalized;

                    return doReadlink(notif, caller_tid, real_path, buf_ptr, bufsiz, logger);
                },
                .tmp => {
                    // Check tombstones
                    supervisor.mutex.lockUncancelable(supervisor.io);
                    defer supervisor.mutex.unlock(supervisor.io);
                    if (supervisor.tombstones.isAncestorTombstoned(h.normalized) or
                        supervisor.tombstones.isTombstoned(h.normalized))
                        return LinuxErr.NOENT;

                    var tmp_buf: [512]u8 = undefined;
                    const real_path = try supervisor.overlay.resolveTmp(h.normalized, &tmp_buf);

                    return doReadlink(notif, caller_tid, real_path, buf_ptr, bufsiz, logger);
                },
                .proc => {
                    // TODO: implement for various proc paths
                    return LinuxErr.INVAL;
                },
            }
        },
    }
}

fn doReadlink(
    notif: linux.SECCOMP.notif,
    caller_tid: AbsTid,
    real_path: []const u8,
    buf_ptr: u64,
    bufsiz: usize,
    logger: anytype,
) !linux.SECCOMP.notif_resp {
    // Null-terminate the path for the kernel
    const nt_buf = OverlayRoot.nullTerminate(real_path) catch return LinuxErr.NAMETOOLONG;

    // Call kernel readlinkat
    var result_buf: [512]u8 = undefined;
    const max_len = @min(bufsiz, result_buf.len);
    const rc = linux.readlinkat(
        linux.AT.FDCWD,
        nt_buf[0..real_path.len :0],
        &result_buf,
        max_len,
    );
    try checkErr(rc, "readlinkat", .{});

    const n: usize = @intCast(rc);

    // Write the symlink target back into the guest's buffer
    try memory_bridge.writeSlice(result_buf[0..n], caller_tid, buf_ptr);

    logger.log("readlinkat: {s} -> {s} ({d} bytes)", .{ real_path, result_buf[0..n], n });
    return replySuccess(notif.id, @intCast(n));
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

fn makeReadlinkatNotif(pid: AbsTid, path: [*:0]const u8, buf: [*]u8, bufsiz: usize) linux.SECCOMP.notif {
    return makeNotif(.readlinkat, .{
        .pid = pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path),
        .arg2 = @intFromPtr(buf),
        .arg3 = bufsiz,
    });
}

fn makeSymlinkatNotif(pid: AbsTid, target: [*:0]const u8, linkpath: [*:0]const u8) linux.SECCOMP.notif {
    return makeNotif(.symlinkat, .{
        .pid = pid,
        .arg0 = @intFromPtr(target),
        .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg2 = @intFromPtr(linkpath),
    });
}

fn initSupervisor(allocator: std.mem.Allocator, stdout_buf: *LogBuffer, stderr_buf: *LogBuffer) !Supervisor {
    return Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, stdout_buf, stderr_buf);
}

test "readlinkat blocked path returns EPERM" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var result_buf: [256]u8 = undefined;
    try testing.expectError(error.PERM, handle(makeReadlinkatNotif(100, "/sys/some_link", &result_buf, result_buf.len), &supervisor));
}

test "readlinkat empty path returns ENOENT" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var result_buf: [256]u8 = undefined;
    try testing.expectError(error.NOENT, handle(makeReadlinkatNotif(100, "", &result_buf, result_buf.len), &supervisor));
}

test "readlinkat unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var result_buf: [256]u8 = undefined;
    try testing.expectError(error.SRCH, handle(makeReadlinkatNotif(999, "relative_link", &result_buf, result_buf.len), &supervisor));
}

test "readlinkat on non-existent path returns ENOENT" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var result_buf: [256]u8 = undefined;
    try testing.expectError(error.NOENT, handle(makeReadlinkatNotif(100, "/tmp/nonexistent_link", &result_buf, result_buf.len), &supervisor));
}

test "readlinkat on tombstoned path returns ENOENT" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const symlinkat_handler = @import("symlinkat.zig");
    _ = try symlinkat_handler.handle(makeSymlinkatNotif(100, "target.txt", "/tmp/test_readlink_tomb"), &supervisor);

    try supervisor.tombstones.add("/tmp/test_readlink_tomb");

    var result_buf: [256]u8 = undefined;
    try testing.expectError(error.NOENT, handle(makeReadlinkatNotif(100, "/tmp/test_readlink_tomb", &result_buf, result_buf.len), &supervisor));
}

test "readlinkat on ancestor-tombstoned path returns ENOENT" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try supervisor.tombstones.add("/tmp/tombstoned_dir");

    var result_buf: [256]u8 = undefined;
    try testing.expectError(error.NOENT, handle(makeReadlinkatNotif(100, "/tmp/tombstoned_dir/link", &result_buf, result_buf.len), &supervisor));
}

test "readlinkat symlink in /tmp returns target" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const symlinkat_handler = @import("symlinkat.zig");
    _ = try symlinkat_handler.handle(makeSymlinkatNotif(100, "target.txt", "/tmp/test_readlink_tmp"), &supervisor);

    var result_buf: [256]u8 = undefined;
    const resp = try handle(makeReadlinkatNotif(100, "/tmp/test_readlink_tmp", &result_buf, result_buf.len), &supervisor);

    const n: usize = @intCast(resp.val);
    try testing.expectEqualStrings("target.txt", result_buf[0..n]);
}

test "readlinkat symlink in COW path returns target" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const symlinkat_handler = @import("symlinkat.zig");
    _ = try symlinkat_handler.handle(makeSymlinkatNotif(100, "/etc/hosts", "/home/test_readlink_cow"), &supervisor);

    var result_buf: [256]u8 = undefined;
    const resp = try handle(makeReadlinkatNotif(100, "/home/test_readlink_cow", &result_buf, result_buf.len), &supervisor);

    const n: usize = @intCast(resp.val);
    try testing.expectEqualStrings("/etc/hosts", result_buf[0..n]);
}

test "readlinkat respects bufsiz limit" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const symlinkat_handler = @import("symlinkat.zig");
    _ = try symlinkat_handler.handle(makeSymlinkatNotif(100, "long_target_name.txt", "/tmp/test_readlink_trunc"), &supervisor);

    var result_buf: [256]u8 = undefined;
    const small_bufsiz: usize = 5;
    const resp = try handle(makeReadlinkatNotif(100, "/tmp/test_readlink_trunc", &result_buf, small_bufsiz), &supervisor);

    const n: usize = @intCast(resp.val);
    try testing.expectEqual(small_bufsiz, n);
    try testing.expectEqualStrings("long_", result_buf[0..n]);
}

test "readlinkat proc path returns EINVAL" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var result_buf: [256]u8 = undefined;
    try testing.expectError(error.INVAL, handle(makeReadlinkatNotif(100, "/proc/self/exe", &result_buf, result_buf.len), &supervisor));
}
