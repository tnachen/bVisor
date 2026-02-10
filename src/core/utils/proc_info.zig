const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const types = @import("../types.zig");
const LinuxResult = types.LinuxResult;

const Thread = @import("../virtual/proc/Thread.zig");
pub const AbsTid = Thread.AbsTid;
pub const NsTid = Thread.NsTid;
pub const AbsTgid = Thread.AbsTgid;
pub const NsTgid = Thread.NsTgid;

const Threads = @import("../virtual/proc/Threads.zig");
pub const CloneFlags = Threads.CloneFlags;
const ThreadStatus = @import("../virtual/proc/ThreadStatus.zig");
const MAX_NS_DEPTH = ThreadStatus.MAX_NS_DEPTH;

// kcmp types from linux/kcmp.h
const KCMP_FILES: u5 = 2;

// =============================================================================
// Test mock state (only compiled in test builds)
// =============================================================================

pub const mock = if (builtin.is_test) struct {
    pub var ptid_map: std.AutoHashMapUnmanaged(AbsTid, AbsTid) = .empty;
    pub var clone_flags: std.AutoHashMapUnmanaged(AbsTid, CloneFlags) = .empty;
    pub var nstids: std.AutoHashMapUnmanaged(AbsTid, []const NsTid) = .empty;
    pub var nstgids: std.AutoHashMapUnmanaged(AbsTid, []const NsTgid) = .empty;
    pub var tgid_map: std.AutoHashMapUnmanaged(AbsTid, AbsTgid) = .empty;

    pub fn reset(allocator: Allocator) void {
        ptid_map.deinit(allocator);
        tgid_map.deinit(allocator);
        clone_flags.deinit(allocator);
        nstids.deinit(allocator);
        nstgids.deinit(allocator);
        ptid_map = .empty;
        tgid_map = .empty;
        clone_flags = .empty;
        nstids = .empty;
        nstgids = .empty;
    }

    pub fn setupParent(allocator: Allocator, child_tid: AbsTid, parent_tid: AbsTid) !void {
        try ptid_map.put(allocator, child_tid, parent_tid);
    }

    pub fn setupCloneFlags(allocator: Allocator, child_tid: AbsTid, flags: CloneFlags) !void {
        try clone_flags.put(allocator, child_tid, flags);
    }

    pub fn setupNsTids(allocator: Allocator, tid: AbsTid, ns_tids: []const NsTid) !void {
        try nstids.put(allocator, tid, ns_tids);
    }

    pub fn setupNsTgids(allocator: Allocator, tid: AbsTid, ns_tgids: []const NsTgid) !void {
        try nstgids.put(allocator, tid, ns_tgids);
    }

    pub fn setupTgid(allocator: Allocator, tid: AbsTid, tgid: AbsTgid) !void {
        try tgid_map.put(allocator, tid, tgid);
    }
} else struct {};

// =============================================================================
// Public API
// =============================================================================

/// Detect clone flags by querying kernel state.
pub fn detectCloneFlags(parent_tid: AbsTid, child_tid: AbsTid) CloneFlags {
    if (comptime builtin.is_test)
        return mock.clone_flags.get(child_tid) orelse CloneFlags{};

    var flags: u64 = 0;
    if (!sameTidNamespace(parent_tid, child_tid)) {
        flags |= linux.CLONE.NEWPID;
    }
    if (sharesFdTable(parent_tid, child_tid)) {
        flags |= linux.CLONE.FILES;
    }
    return CloneFlags.from(flags);
}

/// Read NSpid chain from /proc/[tgid]/task/[tid]/status.
/// Returns NsTids ordered outermost to innermost namespace.
pub fn readNsTids(tgid: AbsTgid, tid: AbsTid, nstid_buf: []NsTid) ![]NsTid {
    if (comptime builtin.is_test) {
        if (mock.nstids.get(tid)) |ns_tids| {
            if (ns_tids.len > nstid_buf.len) return error.BufferTooSmall;
            @memcpy(nstid_buf[0..ns_tids.len], ns_tids);
            return nstid_buf[0..ns_tids.len];
        }
        // Default: single namespace, NsTid = AbsTid
        if (nstid_buf.len < 1) return error.BufferTooSmall;
        nstid_buf[0] = tid;
        return nstid_buf[0..1];
    }

    var path_buf: [64:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/task/{d}/status", .{ tgid, tid }) catch unreachable;

    const fd = try LinuxResult(linux.fd_t).from(
        linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0),
    ).unwrap();
    defer _ = linux.close(fd);

    var file_buf: [4096]u8 = undefined;
    const n = try LinuxResult(usize).from(
        linux.read(fd, &file_buf, file_buf.len),
    ).unwrap();

    var nstids: []NsTid = &.{};
    var lines = std.mem.splitScalar(u8, file_buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "NSpid:")) {
            nstids = try parseNsField(NsTid, line[6..], nstid_buf);
            break;
        }
    }
    if (nstids.len == 0) return error.NSpidNotFound;
    return nstids;
}

/// Get the status of a thread by reading /proc/{tid}/status.
pub fn getStatus(tid: AbsTid) !ThreadStatus {
    if (comptime builtin.is_test) {
        const ptid = mock.ptid_map.get(tid) orelse return error.ThreadNotInKernel;
        const tgid = mock.tgid_map.get(tid) orelse tid;

        var status = ThreadStatus{
            .tid = tid,
            .tgid = tgid,
            .ptid = ptid,
        };

        if (mock.nstgids.get(tid)) |ns_tgids| {
            if (ns_tgids.len > MAX_NS_DEPTH) return error.BufferTooSmall;
            @memcpy(status.nstgids_buf[0..ns_tgids.len], ns_tgids);
            status.nstgids_len = ns_tgids.len;
        } else {
            status.nstgids_buf[0] = tgid;
            status.nstgids_len = 1;
        }

        if (mock.nstids.get(tid)) |ns_tids| {
            if (ns_tids.len > MAX_NS_DEPTH) return error.BufferTooSmall;
            @memcpy(status.nstids_buf[0..ns_tids.len], ns_tids);
            status.nstids_len = ns_tids.len;
        } else {
            status.nstids_buf[0] = tid;
            status.nstids_len = 1;
        }

        return status;
    }

    var path_buf: [32:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/status", .{tid}) catch unreachable;

    const fd = try LinuxResult(linux.fd_t).from(
        linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0),
    ).unwrap();
    defer _ = linux.close(fd);

    var buf: [4096]u8 = undefined;
    const n = try LinuxResult(usize).from(
        linux.read(fd, &buf, buf.len),
    ).unwrap();

    var status = ThreadStatus{
        .tid = tid,
        .tgid = undefined,
        .ptid = undefined,
    };

    var tgid_found: ?AbsTgid = null;
    var ptid_found: ?AbsTid = null;
    var nstgid_found = false;
    var nstid_found = false;

    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "Tgid:")) {
            const tgid_str = std.mem.trim(u8, line[5..], " \t");
            tgid_found = std.fmt.parseInt(AbsTgid, tgid_str, 10) catch return error.ParseError;
        } else if (std.mem.startsWith(u8, line, "PPid:")) {
            const ptid_str = std.mem.trim(u8, line[5..], " \t");
            ptid_found = std.fmt.parseInt(AbsTid, ptid_str, 10) catch return error.ParseError;
        } else if (std.mem.startsWith(u8, line, "NStgid:")) {
            const tgids_str = std.mem.trim(u8, line[7..], " \t");
            var iter = std.mem.tokenizeAny(u8, tgids_str, " \t");
            while (iter.next()) |tgid_str| {
                if (status.nstgids_len >= MAX_NS_DEPTH) return error.BufferTooSmall;
                status.nstgids_buf[status.nstgids_len] = std.fmt.parseInt(NsTgid, tgid_str, 10) catch return error.ParseError;
                status.nstgids_len += 1;
            }
            nstgid_found = true;
        } else if (std.mem.startsWith(u8, line, "NSpid:")) {
            const tids_str = std.mem.trim(u8, line[6..], " \t");
            var iter = std.mem.tokenizeAny(u8, tids_str, " \t");
            while (iter.next()) |tid_str| {
                if (status.nstids_len >= MAX_NS_DEPTH) return error.BufferTooSmall;
                status.nstids_buf[status.nstids_len] = std.fmt.parseInt(NsTid, tid_str, 10) catch return error.ParseError;
                status.nstids_len += 1;
            }
            nstid_found = true;
        }
        if (tgid_found != null and ptid_found != null and nstgid_found and nstid_found) break;
    }

    status.tgid = tgid_found orelse return error.TgidNotFound;
    status.ptid = ptid_found orelse return error.PtidNotFound;
    if (status.nstgids_len == 0) return error.NStgidNotFound;
    if (status.nstids_len == 0) return error.NSpidNotFound;

    return status;
}

/// List all TGIDs from /proc directory.
pub fn listTgids(allocator: Allocator) ![]AbsTgid {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var proc_dir = try std.Io.Dir.openDirAbsolute(io, "/proc", .{ .iterate = true });
    defer proc_dir.close(io);

    var tgids: std.ArrayListUnmanaged(AbsTgid) = .empty;
    errdefer tgids.deinit(allocator);

    var dir_iter = proc_dir.iterate();
    while (try dir_iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const tgid = std.fmt.parseInt(AbsTgid, entry.name, 10) catch continue;
        try tgids.append(allocator, tgid);
    }

    return tgids.toOwnedSlice(allocator);
}

/// List all TIDs from /proc/*/task/* directories.
pub fn listTids(allocator: Allocator) ![]AbsTid {
    if (comptime builtin.is_test) {
        var tids: std.ArrayListUnmanaged(AbsTid) = .empty;
        errdefer tids.deinit(allocator);
        var iter = mock.ptid_map.keyIterator();
        while (iter.next()) |tid_ptr| {
            try tids.append(allocator, tid_ptr.*);
        }
        return tids.toOwnedSlice(allocator);
    }

    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var proc_dir = try std.Io.Dir.openDirAbsolute(io, "/proc", .{ .iterate = true });
    defer proc_dir.close(io);

    var tids: std.ArrayListUnmanaged(AbsTid) = .empty;
    errdefer tids.deinit(allocator);

    var proc_iter = proc_dir.iterate();
    while (try proc_iter.next(io)) |proc_entry| {
        if (proc_entry.kind != .directory) continue;
        const tgid = std.fmt.parseInt(AbsTgid, proc_entry.name, 10) catch continue;

        var task_path_buf: [64]u8 = undefined;
        const task_path = std.fmt.bufPrint(&task_path_buf, "/proc/{d}/task", .{tgid}) catch continue;

        var task_dir = std.Io.Dir.openDirAbsolute(io, task_path, .{ .iterate = true }) catch continue;
        defer task_dir.close(io);

        var task_iter = task_dir.iterate();
        while (try task_iter.next(io)) |task_entry| {
            if (task_entry.kind != .directory) continue;
            const abs_tid = std.fmt.parseInt(AbsTid, task_entry.name, 10) catch continue;
            try tids.append(allocator, abs_tid);
        }
    }

    return tids.toOwnedSlice(allocator);
}

// =============================================================================
// Internal helpers (Linux-only, not compiled in test builds)
// =============================================================================

fn parseNsField(comptime IdType: type, field_data: []const u8, buf: []IdType) ![]IdType {
    const ids_str = std.mem.trim(u8, field_data, " \t");
    var count: usize = 0;
    var iter = std.mem.tokenizeAny(u8, ids_str, " \t");
    while (iter.next()) |id_str| {
        if (count >= buf.len) return error.BufferTooSmall;
        buf[count] = std.fmt.parseInt(IdType, id_str, 10) catch return error.ParseError;
        count += 1;
    }
    if (count == 0) return error.FieldEmpty;
    return buf[0..count];
}

fn sameTidNamespace(tid1: AbsTid, tid2: AbsTid) bool {
    const ino1 = getNsInode(tid1, "pid") orelse return true;
    const ino2 = getNsInode(tid2, "pid") orelse return true;
    return ino1 == ino2;
}

fn getNsInode(tid: AbsTid, ns_type: []const u8) ?u64 {
    var path_buf: [64:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/ns/{s}", .{ tid, ns_type }) catch return null;

    var stat_buf: linux.Statx = undefined;
    LinuxResult(void).from(linux.statx(
        linux.AT.FDCWD,
        path.ptr,
        0,
        @bitCast(linux.STATX{ .INO = true }),
        &stat_buf,
    )).unwrap() catch return null;

    return stat_buf.ino;
}

fn sharesFdTable(tid1: AbsTid, tid2: AbsTid) bool {
    const result = linux.syscall5(
        .kcmp,
        @intCast(tid1),
        @intCast(tid2),
        KCMP_FILES,
        0,
        0,
    );
    return result == 0;
}
