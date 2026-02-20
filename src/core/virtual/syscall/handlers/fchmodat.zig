const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

const AT_EMPTY_PATH: u32 = 0x1000;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {

    // Parse args: fchmodat(dirfd, pathname, mode, flags)
    //   Path-based: changes file permissions on the file at pathname.
    //   FD-based (AT_EMPTY_PATH + null/empty pathname): changes permissions on the file referred to by dirfd.
    const caller_tid: AbsTid = @intCast(notif.pid);
    const dirfd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const path_ptr: u64 = notif.data.arg1;
    const mode: u32 = @truncate(notif.data.arg2);
    const flags: u32 = @truncate(notif.data.arg3);

    // Linux rejects AT_SYMLINK_NOFOLLOW, since symlinks have no mode bits
    if (flags & linux.AT.SYMLINK_NOFOLLOW != 0) return LinuxErr.OPNOTSUPP;

    // pathname may be NULL (pointer == 0) in the AT_EMPTY_PATH case
    var path_buf: [256]u8 = undefined;
    const path: []const u8 = if (path_ptr == 0)
        ""
    else
        try memory_bridge.readString(&path_buf, caller_tid, path_ptr);

    // FD-based: AT_EMPTY_PATH + null/empty pathname
    if ((flags & AT_EMPTY_PATH) != 0 and path.len == 0) {
        if (dirfd >= 0 and dirfd <= 2) return replySuccess(notif.id, 0);

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

        // Virtual proc files have no meaningful mode bits
        if (is_proc) return replySuccess(notif.id, 0);

        if (opened_path_len > 0) {
            // Re-route through path rules for correct COW/tmp isolation.
            // opened_path is already absolute and normalized, so cwd="" is fine.
            const op = opened_path_buf[0..opened_path_len];
            var resolve_buf: [512]u8 = undefined;
            const route_result = resolveAndRoute("", op, &resolve_buf) catch return LinuxErr.NAMETOOLONG;
            return applyRoute(notif, supervisor, route_result, mode);
        }

        // No opened_path: operate on the backing fd directly.
        // writecopy and tmp fds point to overlay files, so this is isolated.
        // readthrough fds point to the real file; fchmod will fail naturally if
        // the sandbox user doesn't own it.
        const backing_fd = file.backingFd() orelse return LinuxErr.BADF;
        const rc = linux.fchmod(backing_fd, mode);
        try checkErr(rc, "fchmodat", .{});
        return replySuccess(notif.id, 0);
    }

    if (path.len == 0) return LinuxErr.INVAL;

    // Path-based: resolve against cwd or dirfd
    var base_buf: [512]u8 = undefined;
    const base: []const u8 = blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        if (path[0] != '/' and dirfd != linux.AT.FDCWD) {
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

    return applyRoute(notif, supervisor, route_result, mode);
}

fn applyRoute(
    notif: linux.SECCOMP.notif,
    supervisor: *Supervisor,
    route_result: path_router.ResolvedRouteResult,
    mode: u32,
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

            try File.fchmodatByPath(h.backend, &supervisor.overlay, h.normalized, mode);
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

fn makeFchmodatNotif(pid: AbsTid, path: [*:0]const u8, mode: u32) linux.SECCOMP.notif {
    return makeNotif(.fchmodat, .{
        .pid = pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path),
        .arg2 = mode,
        .arg3 = 0,
    });
}

test "fchmodat blocked path /sys returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.PERM, handle(makeFchmodatNotif(init_tid, "/sys/class", 0o755), &supervisor));
}

test "fchmodat AT_SYMLINK_NOFOLLOW returns EOPNOTSUPP" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.fchmodat, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/bin/ls")),
        .arg2 = 0o755,
        .arg3 = linux.AT.SYMLINK_NOFOLLOW,
    });
    try testing.expectError(error.OPNOTSUPP, handle(notif, &supervisor));
}

test "fchmodat non-existent COW path returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.NOENT, handle(makeFchmodatNotif(init_tid, "/nonexistent_bvisor_fchmodat_test", 0o755), &supervisor));
}

test "fchmodat unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.SRCH, handle(makeFchmodatNotif(999, "/bin/ls", 0o755), &supervisor));
}

test "fchmodat creates COW copy for existing real file" {
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

    const resp = try handle(makeFchmodatNotif(init_tid, ls_path, 0o755), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
    try testing.expect(supervisor.overlay.cowExists(ls_path));
}

test "fchmodat AT_EMPTY_PATH unknown fd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.fchmodat, .{
        .pid = init_tid,
        .arg0 = @as(u64, 42), // fd not in table
        .arg1 = @intFromPtr(@as([*:0]const u8, "")),
        .arg2 = 0o755,
        .arg3 = AT_EMPTY_PATH,
    });
    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "fchmodat AT_EMPTY_PATH with proc fd is no-op" {
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

    const notif = makeNotif(.fchmodat, .{
        .pid = init_tid,
        .arg0 = @as(u64, @intCast(vfd)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "")),
        .arg2 = 0o755,
        .arg3 = AT_EMPTY_PATH,
    });
    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
}
