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
