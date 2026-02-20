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

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: symlinkat(target, newdirfd, linkpath)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const target_ptr: u64 = notif.data.arg0;
    const newdirfd: i32 = @truncate(@as(i64, @bitCast(notif.data.arg1)));
    const linkpath_ptr: u64 = notif.data.arg2;

    var target_buf: [256]u8 = undefined;
    const target = try memory_bridge.readString(&target_buf, caller_tid, target_ptr);

    var linkpath_buf: [256]u8 = undefined;
    const linkpath = try memory_bridge.readString(&linkpath_buf, caller_tid, linkpath_ptr);

    if (linkpath.len == 0) return LinuxErr.NOENT;
    if (target.len == 0) return LinuxErr.NOENT;

    // Resolve base directory for linkpath
    var base_buf: [512]u8 = undefined;
    const base: []const u8 = if (linkpath[0] == '/') "/" else blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        if (newdirfd != linux.AT.FDCWD) {
            const dir_file = caller.fd_table.get_ref(newdirfd) orelse {
                logger.log("symlinkat: EBADF for newdirfd={d}", .{newdirfd});
                return LinuxErr.BADF;
            };
            defer dir_file.unref();

            const dir_path = dir_file.opened_path orelse {
                logger.log("symlinkat: newdirfd={d} has no associated path", .{newdirfd});
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
    const route_result = resolveAndRoute(base, linkpath, &resolve_buf) catch {
        return LinuxErr.NAMETOOLONG;
    };

    switch (route_result) {
        .block => {
            logger.log("symlinkat: blocked path: {s}", .{linkpath});
            return LinuxErr.PERM;
        },
        .handle => |h| {
            switch (h.backend) {
                .event => unreachable, // eventfd are not opened via path routing
                .passthrough, .proc => return LinuxErr.PERM,
                .cow => {
                    try handleCowSymlink(target, h.normalized, supervisor);
                    logger.log("symlinkat: created {s} -> {s} in cow overlay", .{ h.normalized, target });
                    return replySuccess(notif.id, 0);
                },
                .tmp => {
                    try handleTmpSymlink(target, h.normalized, supervisor);
                    logger.log("symlinkat: created {s} -> {s} in tmp overlay", .{ h.normalized, target });
                    return replySuccess(notif.id, 0);
                },
            }
        },
    }
}

fn handleCowSymlink(target: []const u8, normalized: []const u8, supervisor: *Supervisor) !void {
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        if (supervisor.tombstones.isAncestorTombstoned(normalized)) {
            return LinuxErr.NOENT;
        }

        if (supervisor.tombstones.isTombstoned(normalized)) {
            supervisor.tombstones.remove(normalized);
        } else {
            if (supervisor.overlay.cowExists(normalized) or OverlayRoot.pathExistsOnRealFs(normalized)) {
                return LinuxErr.EXIST;
            }
        }

        const parent = std.fs.path.dirname(normalized) orelse "/";
        if (!supervisor.overlay.cowExists(parent) and !OverlayRoot.pathExistsOnRealFs(parent)) {
            return LinuxErr.NOENT;
        }
        if (!supervisor.overlay.isGuestDir(parent)) {
            return LinuxErr.NOTDIR;
        }
    }

    try Cow.symlink(&supervisor.overlay, target, normalized);
}

fn handleTmpSymlink(target: []const u8, normalized: []const u8, supervisor: *Supervisor) !void {
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        if (supervisor.tombstones.isAncestorTombstoned(normalized)) {
            return LinuxErr.NOENT;
        }

        if (supervisor.tombstones.isTombstoned(normalized)) {
            supervisor.tombstones.remove(normalized);
        } else {
            if (supervisor.overlay.tmpExists(normalized)) {
                return LinuxErr.EXIST;
            }
        }

        const parent = std.fs.path.dirname(normalized) orelse "/tmp";
        if (!std.mem.eql(u8, parent, "/tmp")) {
            if (supervisor.tombstones.isTombstoned(parent)) {
                return LinuxErr.NOENT;
            }
            if (!supervisor.overlay.tmpExists(parent)) {
                return LinuxErr.NOENT;
            }
            if (!supervisor.overlay.isTmpDir(parent)) {
                return LinuxErr.NOTDIR;
            }
        }
    }

    try Tmp.symlink(&supervisor.overlay, target, normalized);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

fn makeSymlinkatNotif(pid: AbsTid, target: [*:0]const u8, linkpath: [*:0]const u8) linux.SECCOMP.notif {
    return makeNotif(.symlinkat, .{
        .pid = pid,
        .arg0 = @intFromPtr(target),
        .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg2 = @intFromPtr(linkpath),
    });
}

fn initTestSupervisor(allocator: std.mem.Allocator, stdout_buf: *LogBuffer, stderr_buf: *LogBuffer) !Supervisor {
    const init_tid: AbsTid = 100;
    return Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, stdout_buf, stderr_buf);
}

test "symlinkat in /tmp creates symlink" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = try handle(makeSymlinkatNotif(100, "/some/target", "/tmp/test_symlink"), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
    try testing.expect(supervisor.overlay.tmpExists("/tmp/test_symlink"));
}

test "symlinkat on COW path creates in overlay" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /home exists on real FS (Alpine)
    const resp = try handle(makeSymlinkatNotif(100, "../relative/target", "/home/bvisor_test_symlink"), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
    try testing.expect(supervisor.overlay.cowExists("/home/bvisor_test_symlink"));
}

test "symlinkat blocked path returns EPERM" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.PERM, handle(makeSymlinkatNotif(100, "target", "/sys/newlink"), &supervisor));
}

test "symlinkat on passthrough path returns EPERM" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.PERM, handle(makeSymlinkatNotif(100, "target", "/dev/null"), &supervisor));
}

test "symlinkat on proc path returns EPERM" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.PERM, handle(makeSymlinkatNotif(100, "target", "/proc/newlink"), &supervisor));
}

test "symlinkat empty linkpath returns ENOENT" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.NOENT, handle(makeSymlinkatNotif(100, "target", ""), &supervisor));
}

test "symlinkat empty target returns ENOENT" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.NOENT, handle(makeSymlinkatNotif(100, "", "/tmp/test_symlink_empty"), &supervisor));
}

test "symlinkat unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Relative path forces cwd lookup, which fails for unknown TID
    try testing.expectError(error.SRCH, handle(makeSymlinkatNotif(999, "target", "relative_link"), &supervisor));
}

test "symlinkat on existing COW path returns EEXIST" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /etc/hostname exists on the real filesystem
    try testing.expectError(error.EXIST, handle(makeSymlinkatNotif(100, "target", "/etc/hostname"), &supervisor));
}

test "symlinkat on existing tmp file returns EEXIST" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a symlink first
    const resp = try handle(makeSymlinkatNotif(100, "target1", "/tmp/test_symlink_dup"), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Try to create another symlink at the same path
    try testing.expectError(error.EXIST, handle(makeSymlinkatNotif(100, "target2", "/tmp/test_symlink_dup"), &supervisor));
}

test "symlinkat with non-existent parent returns ENOENT" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.NOENT, handle(makeSymlinkatNotif(100, "target", "/tmp/nonexistent/link"), &supervisor));
}

test "symlinkat with non-existent COW parent returns ENOENT" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.NOENT, handle(makeSymlinkatNotif(100, "target", "/nonexistent_dir/link"), &supervisor));
}

test "symlinkat with file as parent on COW path returns ENOTDIR" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /etc/hostname is a file, not a directory
    try testing.expectError(error.NOTDIR, handle(makeSymlinkatNotif(100, "target", "/etc/hostname/link"), &supervisor));
}

test "symlinkat with file as parent on tmp path returns ENOTDIR" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a file in /tmp via openat
    const openat = @import("openat.zig");
    const openat_notif = makeNotif(.openat, .{
        .pid = @as(AbsTid, 100),
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/tmp/test_symlink_notdir_file")),
        .arg2 = @as(u32, @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true })),
        .arg3 = @as(u64, 0o644),
    });
    const open_resp = try openat.handle(openat_notif, &supervisor);
    try testing.expect(open_resp.val >= 3);

    try testing.expectError(error.NOTDIR, handle(makeSymlinkatNotif(100, "target", "/tmp/test_symlink_notdir_file/link"), &supervisor));
}

test "symlinkat on tombstoned tmp path succeeds and clears tombstone" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create symlink, then unlink it (tombstones + physically removes), then re-create
    const resp1 = try handle(makeSymlinkatNotif(100, "target1", "/tmp/test_symlink_tomb"), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp1.val);

    const unlinkat = @import("unlinkat.zig");
    const unlink_notif = makeNotif(.unlinkat, .{
        .pid = @as(AbsTid, 100),
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/tmp/test_symlink_tomb")),
        .arg2 = @as(u64, 0),
    });
    _ = try unlinkat.handle(unlink_notif, &supervisor);
    try testing.expect(supervisor.tombstones.isTombstoned("/tmp/test_symlink_tomb"));

    const resp2 = try handle(makeSymlinkatNotif(100, "target2", "/tmp/test_symlink_tomb"), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp2.val);

    try testing.expect(!supervisor.tombstones.isTombstoned("/tmp/test_symlink_tomb"));
    try testing.expect(supervisor.overlay.tmpExists("/tmp/test_symlink_tomb"));
}

test "symlinkat on tombstoned COW path succeeds and clears tombstone" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /etc/hostname exists on real FS. Tombstone it, then symlink over it.
    try supervisor.tombstones.add("/etc/hostname");
    try testing.expect(supervisor.tombstones.isTombstoned("/etc/hostname"));

    const resp = try handle(makeSymlinkatNotif(100, "target", "/etc/hostname"), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    try testing.expect(!supervisor.tombstones.isTombstoned("/etc/hostname"));
    try testing.expect(supervisor.overlay.cowExists("/etc/hostname"));
}

test "symlinkat with ancestor tombstoned returns ENOENT on tmp" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a directory then tombstone it
    const mkdirat = @import("mkdirat.zig");
    const mkdir_notif = makeNotif(.mkdirat, .{
        .pid = @as(AbsTid, 100),
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/tmp/test_ancestor_tomb")),
        .arg2 = @as(u64, 0o755),
    });
    _ = try mkdirat.handle(mkdir_notif, &supervisor);

    try supervisor.tombstones.add("/tmp/test_ancestor_tomb");

    try testing.expectError(error.NOENT, handle(makeSymlinkatNotif(100, "target", "/tmp/test_ancestor_tomb/link"), &supervisor));
}

test "symlinkat with ancestor tombstoned returns ENOENT on COW" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try initTestSupervisor(allocator, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /etc exists on real FS. Tombstone it.
    try supervisor.tombstones.add("/etc");

    try testing.expectError(error.NOENT, handle(makeSymlinkatNotif(100, "target", "/etc/new_symlink"), &supervisor));
}
