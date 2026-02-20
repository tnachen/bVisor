const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const OverlayRoot = @import("../../OverlayRoot.zig");
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");
const Cow = @import("../../fs/backend/cow.zig").Cow;
const Tmp = @import("../../fs/backend/tmp.zig").Tmp;

const AT_EMPTY_PATH: u32 = 0x1000;

// utimensat(dirfd, pathname, times, flags)
//   Path-based: sets timestamps on the file at pathname, routed through COW/tmp/passthrough/proc rules.
//   FD-based (AT_EMPTY_PATH + null/empty pathname): operates on the file referred to by dirfd.
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const caller_tid: AbsTid = @intCast(notif.pid);
    const dirfd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const pathname_ptr: u64 = notif.data.arg1;
    const times_ptr: u64 = notif.data.arg2;
    const flags: u32 = @truncate(notif.data.arg3);

    var times_storage: [2]linux.timespec = undefined;
    const times_arg: ?*const [2]linux.timespec = if (times_ptr != 0) blk: {
        times_storage = try memory_bridge.read([2]linux.timespec, caller_tid, times_ptr);
        break :blk &times_storage;
    } else null;

    // pathname may be NULL (pointer == 0) in the AT_EMPTY_PATH case
    var path_buf: [256]u8 = undefined;
    const path: []const u8 = if (pathname_ptr == 0)
        ""
    else
        try memory_bridge.readString(&path_buf, caller_tid, pathname_ptr);

    // FD-based: AT_EMPTY_PATH + null/empty pathname
    if ((flags & AT_EMPTY_PATH) != 0 and path.len == 0) {
        // stdio fds are kernel-managed; backing fds installed via addfd match 1:1
        if (dirfd >= 0 and dirfd <= 2) {
            const rc = linux.utimensat(dirfd, null, times_arg, linux.AT.EMPTY_PATH);
            try checkErr(rc, "utimensat", .{});
            return replySuccess(notif.id, 0);
        }

        var file: *File = undefined;
        var opened_path_buf: [512]u8 = undefined;
        var opened_path_len: usize = 0;
        var is_proc: bool = false;

        {
            supervisor.mutex.lockUncancelable(supervisor.io);
            defer supervisor.mutex.unlock(supervisor.io);

            const caller = try supervisor.guest_threads.get(caller_tid);
            file = caller.fd_table.get_ref(dirfd) orelse return LinuxErr.BADF;

            if (file.opened_path) |p| {
                if (p.len <= opened_path_buf.len) {
                    @memcpy(opened_path_buf[0..p.len], p);
                    opened_path_len = p.len;
                }
            }
            is_proc = switch (file.backend) {
                .proc => true,
                else => false,
            };
        }
        defer file.unref();

        if (is_proc) return replySuccess(notif.id, 0);

        if (opened_path_len > 0) {
            // Re-route through path rules for correct COW/tmp isolation.
            // opened_path is already absolute and normalized, so cwd="" is fine.
            const op = opened_path_buf[0..opened_path_len];
            var resolve_buf: [512]u8 = undefined;
            const route_result = resolveAndRoute("", op, &resolve_buf) catch return LinuxErr.NAMETOOLONG;
            return applyRoute(notif, supervisor, route_result, times_arg);
        }

        // No opened_path: operate on the backing fd directly.
        // writecopy and tmp fds point to overlay files, so this is isolated.
        // readthrough fds point to the real file; utimensat will fail naturally if
        // the sandbox user doesn't own the file.
        const backing_fd = file.backingFd() orelse return LinuxErr.BADF;
        const rc = linux.utimensat(backing_fd, null, times_arg, linux.AT.EMPTY_PATH);
        try checkErr(rc, "utimensat", .{});
        return replySuccess(notif.id, 0);
    }

    // Path-based: resolve against cwd or dirfd
    var base_buf: [512]u8 = undefined;
    const base: []const u8 = blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        if (path.len > 0 and path[0] != '/' and dirfd != linux.AT.FDCWD) {
            const dir_file = caller.fd_table.get_ref(dirfd) orelse return LinuxErr.BADF;
            defer dir_file.unref();
            const dir_path = dir_file.opened_path orelse return LinuxErr.NOTDIR;
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
    const route_result = resolveAndRoute(base, path, &resolve_buf) catch return LinuxErr.NAMETOOLONG;
    return applyRoute(notif, supervisor, route_result, times_arg);
}

fn applyRoute(
    notif: linux.SECCOMP.notif,
    supervisor: *Supervisor,
    route_result: path_router.ResolvedRouteResult,
    times_arg: ?*const [2]linux.timespec,
) !linux.SECCOMP.notif_resp {
    switch (route_result) {
        .block => return LinuxErr.PERM,
        .handle => |h| {
            if (h.backend == .cow or h.backend == .tmp) {
                supervisor.mutex.lockUncancelable(supervisor.io);
                defer supervisor.mutex.unlock(supervisor.io);
                if (supervisor.tombstones.isTombstoned(h.normalized) or
                    supervisor.tombstones.isAncestorTombstoned(h.normalized))
                {
                    return LinuxErr.NOENT;
                }
            }

            switch (h.backend) {
                .passthrough => {
                    const nt = OverlayRoot.nullTerminate(h.normalized) catch return LinuxErr.NAMETOOLONG;
                    const rc = linux.utimensat(linux.AT.FDCWD, nt[0..h.normalized.len :0], times_arg, 0);
                    try checkErr(rc, "utimensat", .{});
                },
                .cow => try Cow.utimensat(&supervisor.overlay, h.normalized, times_arg),
                .tmp => try Tmp.utimensat(&supervisor.overlay, h.normalized, times_arg),
                .proc => {}, // virtual proc files: timestamps are not meaningful
            }
            return replySuccess(notif.id, 0);
        },
    }
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const builtin = @import("builtin");

const ls_path = "/bin/ls";

test "utimensat blocked path /sys returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.utimensat, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/sys/class")),
        .arg2 = 0,
        .arg3 = 0,
    });
    try testing.expectError(error.PERM, handle(notif, &supervisor));
}

test "utimensat non-existent COW path returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.utimensat, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/nonexistent_bvisor_utimensat_test")),
        .arg2 = 0,
        .arg3 = 0,
    });
    try testing.expectError(error.NOENT, handle(notif, &supervisor));
}

test "utimensat creates COW copy for existing real file" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expect(!supervisor.overlay.cowExists(ls_path));

    const notif = makeNotif(.utimensat, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, ls_path)),
        .arg2 = 0, // times = NULL -> set to current time
        .arg3 = 0,
    });
    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
    try testing.expect(supervisor.overlay.cowExists(ls_path));
}

test "utimensat sets specific mtime on COW copy" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var times: [2]linux.timespec = .{
        .{ .sec = 111111, .nsec = 0 }, // atime
        .{ .sec = 222222, .nsec = 0 }, // mtime
    };
    const notif = makeNotif(.utimensat, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, ls_path)),
        .arg2 = @intFromPtr(&times),
        .arg3 = 0,
    });
    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    const statx_result = try Cow.statxByPath(&supervisor.overlay, ls_path);
    try testing.expect(statx_result.mask.MTIME);
    try testing.expectEqual(@as(i64, 222222), statx_result.mtime.sec);
}

test "utimensat AT_EMPTY_PATH unknown fd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.utimensat, .{
        .pid = init_tid,
        .arg0 = @as(u64, 42), // fd not in table
        .arg1 = @intFromPtr(@as([*:0]const u8, "")),
        .arg2 = 0,
        .arg3 = AT_EMPTY_PATH,
    });
    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "utimensat AT_EMPTY_PATH with proc fd is no-op" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const thread = supervisor.guest_threads.lookup.get(init_tid).?;
    var proc_content: [256]u8 = undefined;
    @memcpy(proc_content[0..4], "100\n");
    const file = try File.init(allocator, .{ .proc = .{
        .content = proc_content,
        .content_len = 4,
        .offset = 0,
    } });
    const vfd = try thread.fd_table.insert(file, .{});

    const notif = makeNotif(.utimensat, .{
        .pid = init_tid,
        .arg0 = @as(u64, @intCast(vfd)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "")),
        .arg2 = 0,
        .arg3 = AT_EMPTY_PATH,
    });
    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
}
