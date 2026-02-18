const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
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

// mkdirat(dirfd, pathname, mode)
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    const caller_tid: AbsTid = @intCast(notif.pid);
    const dirfd: i32 = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    const path_ptr: u64 = notif.data.arg1;
    const mode: linux.mode_t = @truncate(notif.data.arg2);

    var path_buf: [256]u8 = undefined;
    const path = try memory_bridge.readString(&path_buf, caller_tid, path_ptr);

    if (path.len == 0) {
        return LinuxErr.INVAL;
    }

    // Resolve base directory
    var base_buf: [512]u8 = undefined;
    const base: []const u8 = if (path[0] == '/') "/" else blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        if (dirfd != linux.AT.FDCWD) {
            const dir_file = caller.fd_table.get_ref(dirfd) orelse {
                logger.log("mkdirat: EBADF for dirfd={d}", .{dirfd});
                return LinuxErr.BADF;
            };
            defer dir_file.unref();

            const dir_path = dir_file.opened_path orelse {
                logger.log("mkdirat: dirfd={d} has no associated path", .{dirfd});
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
    const route_result = resolveAndRoute(base, path, &resolve_buf) catch {
        return LinuxErr.NAMETOOLONG;
    };

    switch (route_result) {
        .block => {
            logger.log("mkdirat: blocked path: {s}", .{path});
            return LinuxErr.PERM;
        },
        .handle => |h| {
            switch (h.backend) {
                .passthrough, .proc => return LinuxErr.PERM,
                .cow => {
                    try handleCowMkdir(h.normalized, mode, supervisor);
                    logger.log("mkdirat: created {s} in cow overlay", .{h.normalized});
                    return replySuccess(notif.id, 0);
                },
                .tmp => {
                    try handleTmpMkdir(h.normalized, mode, supervisor);
                    logger.log("mkdirat: created {s} in tmp overlay", .{h.normalized});
                    return replySuccess(notif.id, 0);
                },
            }
        },
    }
}

fn handleCowMkdir(normalized: []const u8, mode: linux.mode_t, supervisor: *Supervisor) !void {
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        if (supervisor.tombstones.isTombstoned(normalized)) {
            supervisor.tombstones.remove(normalized);
            // Physical dir may still exist from before tombstoning
            if (supervisor.overlay.cowExists(normalized)) return;
        } else {
            if (supervisor.overlay.cowExists(normalized) or OverlayRoot.pathExistsOnRealFs(normalized)) {
                return error.EXIST;
            }
        }

        // Check parent exists from guest perspective
        const parent = std.fs.path.dirname(normalized) orelse "/";
        if (supervisor.tombstones.isTombstoned(parent)) {
            return error.NOENT;
        }
        if (!supervisor.overlay.cowExists(parent) and !OverlayRoot.pathExistsOnRealFs(parent)) {
            return error.NOENT;
        }
    }

    try Cow.mkdir(&supervisor.overlay, normalized, mode);
}

fn handleTmpMkdir(normalized: []const u8, mode: linux.mode_t, supervisor: *Supervisor) !void {
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        if (supervisor.tombstones.isTombstoned(normalized)) {
            supervisor.tombstones.remove(normalized);
            // Physical dir may still exist from before tombstoning
            if (supervisor.overlay.tmpExists(normalized)) return;
        } else {
            if (supervisor.overlay.tmpExists(normalized)) {
                return error.EXIST;
            }
        }

        // /tmp itself always exists; other parents must exist in overlay
        const parent = std.fs.path.dirname(normalized) orelse "/tmp";
        if (!std.mem.eql(u8, parent, "/tmp")) {
            if (supervisor.tombstones.isTombstoned(parent)) {
                return error.NOENT;
            }
            if (!supervisor.overlay.tmpExists(parent)) {
                return error.NOENT;
            }
        }
    }

    try Tmp.mkdir(&supervisor.overlay, normalized, mode);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

fn makeMkdiratNotif(pid: AbsTid, path: [*:0]const u8, mode: u32) linux.SECCOMP.notif {
    return makeNotif(.mkdirat, .{
        .pid = pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path),
        .arg2 = mode,
    });
}

test "mkdirat blocked path returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.PERM, handle(makeMkdiratNotif(init_tid, "/sys/newdir", 0o755), &supervisor));
}

test "mkdirat in /tmp creates directory" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = try handle(makeMkdiratNotif(init_tid, "/tmp/test_mkdir_new", 0o755), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Verify the directory exists in the tmp overlay
    try testing.expect(supervisor.overlay.tmpExists("/tmp/test_mkdir_new"));
}

test "mkdirat on existing real path returns EEXIST" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /etc exists on the real filesystem
    try testing.expectError(error.EXIST, handle(makeMkdiratNotif(init_tid, "/etc", 0o755), &supervisor));
}

test "mkdirat on tombstoned path succeeds" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create, then tombstone, then re-create
    const resp1 = try handle(makeMkdiratNotif(init_tid, "/tmp/test_mkdir_tomb", 0o755), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp1.val);

    try supervisor.tombstones.add("/tmp/test_mkdir_tomb", .dir);

    const resp2 = try handle(makeMkdiratNotif(init_tid, "/tmp/test_mkdir_tomb", 0o755), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp2.val);

    // Tombstone should be removed
    try testing.expect(!supervisor.tombstones.isTombstoned("/tmp/test_mkdir_tomb"));
}

test "mkdirat with non-existent parent returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /tmp/nonexistent doesn't exist, so can't create /tmp/nonexistent/subdir
    try testing.expectError(error.NOENT, handle(makeMkdiratNotif(init_tid, "/tmp/nonexistent/subdir", 0o755), &supervisor));
}

test "mkdirat unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Use relative path so handler must look up caller's cwd, triggering ESRCH
    try testing.expectError(error.SRCH, handle(makeMkdiratNotif(999, "test_dir", 0o755), &supervisor));
}

test "mkdirat on COW path creates in overlay" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /home exists on real FS (Alpine has it), create a subdir
    const resp = try handle(makeMkdiratNotif(init_tid, "/home/bvisor_test_mkdir", 0o755), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Verify it exists in COW overlay
    try testing.expect(supervisor.overlay.cowExists("/home/bvisor_test_mkdir"));
}
