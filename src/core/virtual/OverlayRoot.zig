const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("../linux_error.zig").checkErr;

const Self = @This();

fn sysOpenat(path: []const u8, flags: linux.O, mode: linux.mode_t) !linux.fd_t {
    const buf = nullTerminate(path) catch return error.NAMETOOLONG;
    const rc = linux.openat(linux.AT.FDCWD, buf[0..path.len :0], flags, mode);
    try checkErr(rc, "OverlayRoot.sysOpenat", .{});
    return @intCast(rc);
}

uid: [16]u8,
root_path_buf: [root_fmt_str.len + 16]u8,
root_path_len: usize,
root_dir: std.Io.Dir,
io: std.Io,

const root_fmt_str = "/tmp/.bvisor/sb/{s}";
const subdirs = .{ "cow", "tmp" };

/// Returns the root path as a slice.
pub fn rootPath(self: *const Self) []const u8 {
    return self.root_path_buf[0..self.root_path_len];
}

pub fn init(io: std.Io, uid: [16]u8) !Self {
    var self = Self{
        .uid = uid,
        .root_path_buf = undefined,
        .root_path_len = 0,
        .root_dir = undefined,
        .io = io,
    };
    const path = std.fmt.bufPrint(&self.root_path_buf, root_fmt_str, .{uid}) catch return error.NAMETOOLONG;
    self.root_path_len = path.len;
    self.root_dir = try std.Io.Dir.cwd().createDirPathOpen(io, path, .{});

    inline for (subdirs) |subdir| {
        _ = try self.root_dir.createDirPathOpen(io, subdir, .{});
    }

    return self;
}

pub fn deinit(self: *Self) void {
    self.root_dir.close(self.io);
    const parent_dir = std.Io.Dir.openDirAbsolute(self.io, "/tmp/.bvisor/sb", .{}) catch return;
    defer parent_dir.close(self.io);
    parent_dir.deleteTree(self.io, &self.uid) catch |err| {
        std.debug.print("Warning: Failed to delete overlay root: {s}\n", .{@errorName(err)});
    };
}

/// Creates necessary parent directories when copying to COW
/// eg open /usr/bin/ls for write should populate sandbox's cow dir with /usr/bin
pub fn createCowParentDirs(self: *Self, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    const relative_parent = if (parent.len > 0 and parent[0] == '/') parent[1..] else parent;
    if (relative_parent.len == 0) return;
    var subpath_buf: [512]u8 = undefined;
    const subpath = std.fmt.bufPrint(&subpath_buf, "cow/{s}", .{relative_parent}) catch return error.NAMETOOLONG;
    self.root_dir.createDirPath(self.io, subpath) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

/// Resolves a path to its COW overlay location.
/// e.g., /usr/bin/ls -> {root_path}/cow/usr/bin/ls
pub fn resolveCow(self: *const Self, path: []const u8, buf: []u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/cow{s}", .{ self.rootPath(), path }) catch error.NAMETOOLONG;
}

/// Resolves a path to its tmp overlay location.
/// e.g., /tmp/foo -> {root_path}/tmp/foo (strips /tmp prefix)
pub fn resolveTmp(self: *const Self, path: []const u8, buf: []u8) ![]const u8 {
    const tmp_prefix = "/tmp";
    if (!std.mem.startsWith(u8, path, tmp_prefix)) {
        return error.InvalidPath;
    }
    // Strip /tmp prefix: /tmp/foo -> /foo, then format as {root_path}/tmp/foo
    const suffix = path[tmp_prefix.len..];
    return std.fmt.bufPrint(buf, "{s}/tmp{s}", .{ self.rootPath(), suffix }) catch error.NAMETOOLONG;
}

/// Null-terminate a path into a stack buffer for kernel syscalls.
pub fn nullTerminate(path: []const u8) ![513]u8 {
    if (path.len > 512) return error.NAMETOOLONG;
    var buf: [513]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf;
}

/// Check if a path exists on the real (kernel) filesystem.
pub fn pathExistsOnRealFs(path: []const u8) bool {
    const buf = nullTerminate(path) catch return false;
    const rc = linux.faccessat(linux.AT.FDCWD, buf[0..path.len :0], linux.F_OK, 0);
    return linux.errno(rc) == .SUCCESS;
}

/// Check if a path is a directory on the real (kernel) filesystem.
pub fn isRealDir(path: []const u8) bool {
    const buf = nullTerminate(path) catch return false;
    var statx_buf: linux.Statx = std.mem.zeroes(linux.Statx);
    const rc = linux.statx(
        linux.AT.FDCWD,
        buf[0..path.len :0],
        0,
        @bitCast(linux.STATX{ .TYPE = true }),
        &statx_buf,
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    return (statx_buf.mode & linux.S.IFMT) == linux.S.IFDIR;
}

/// Check if a path at a given overlay location is a directory.
pub fn isCowDir(self: *const Self, path: []const u8) bool {
    var cow_buf: [512]u8 = undefined;
    const cow_path = self.resolveCow(path, &cow_buf) catch return false;
    return isRealDir(cow_path);
}

/// Check if a path at a given tmp overlay location is a directory.
pub fn isTmpDir(self: *const Self, path: []const u8) bool {
    var tmp_buf: [512]u8 = undefined;
    const tmp_path = self.resolveTmp(path, &tmp_buf) catch return false;
    return isRealDir(tmp_path);
}

/// Check if a path exists in the tmp overlay.
pub fn tmpExists(self: *const Self, path: []const u8) bool {
    var buf: [512]u8 = undefined;
    const tmp_path = self.resolveTmp(path, &buf) catch return false;
    return pathExistsOnRealFs(tmp_path);
}

/// Checks if a COW copy exists for the given path.
pub fn cowExists(self: *const Self, path: []const u8) bool {
    var buf: [512]u8 = undefined;
    const cow_path = self.resolveCow(path, &buf) catch return false;
    // Try to open the file - if it succeeds, it exists
    const fd = sysOpenat(cow_path, .{ .ACCMODE = .RDONLY }, 0) catch return false;
    _ = linux.close(fd);
    return true;
}

/// Check if a path exists from the guest's perspective (COW overlay or real FS).
pub fn guestPathExists(self: *const Self, path: []const u8) bool {
    return self.cowExists(path) or pathExistsOnRealFs(path);
}

/// Check if a path is a directory from the guest's perspective.
/// Checks COW overlay first, then real FS.
pub fn isGuestDir(self: *const Self, path: []const u8) bool {
    if (self.cowExists(path)) {
        return self.isCowDir(path);
    }
    return isRealDir(path);
}

const testing = std.testing;

test "init creates cow and tmp subdirectories" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0001".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    // Verify cow subdir exists
    var cow_buf: [512]u8 = undefined;
    const cow_dir = std.fmt.bufPrint(&cow_buf, "{s}/cow", .{overlay.rootPath()}) catch unreachable;
    try std.Io.Dir.accessAbsolute(io, cow_dir, .{});

    // Verify tmp subdir exists
    var tmp_buf: [512]u8 = undefined;
    const tmp_dir = std.fmt.bufPrint(&tmp_buf, "{s}/tmp", .{overlay.rootPath()}) catch unreachable;
    try std.Io.Dir.accessAbsolute(io, tmp_dir, .{});
}

test "root path formatted as /tmp/.bvisor/sb/{uid}" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0002".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    const expected = try std.fmt.allocPrint(testing.allocator, "/tmp/.bvisor/sb/{s}", .{uid});
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, overlay.rootPath());
}

test "resolveCow maps /etc/passwd to overlay cow dir" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0003".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    var buf: [512]u8 = undefined;
    const resolved = try overlay.resolveCow("/etc/passwd", &buf);
    const expected = try std.fmt.allocPrint(testing.allocator, "/tmp/.bvisor/sb/{s}/cow/etc/passwd", .{uid});
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, resolved);
}

test "resolveTmp maps /tmp/myfile to overlay tmp dir" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0004".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    var buf: [512]u8 = undefined;
    const resolved = try overlay.resolveTmp("/tmp/myfile", &buf);
    const expected = try std.fmt.allocPrint(testing.allocator, "/tmp/.bvisor/sb/{s}/tmp/myfile", .{uid});
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, resolved);
}

test "resolveTmp on non-/tmp path returns InvalidPath" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0005".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    var buf: [512]u8 = undefined;
    try testing.expectError(error.InvalidPath, overlay.resolveTmp("/etc/passwd", &buf));
}

test "cowExists before any COW returns false" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0006".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    try testing.expect(!overlay.cowExists("/etc/passwd"));
}

test "cowExists after creating COW copy returns true" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0007".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    // Manually create a cow file to simulate copyFile
    try overlay.createCowParentDirs("/etc/passwd");
    var buf: [512]u8 = undefined;
    const cow_path = try overlay.resolveCow("/etc/passwd", &buf);
    const fd = try sysOpenat(cow_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    _ = linux.close(fd);

    try testing.expect(overlay.cowExists("/etc/passwd"));
}

test "deinit deletes root directory tree" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0008".*;
    var overlay = try Self.init(io, uid);

    // Capture root path before deinit
    var root_buf: [128]u8 = undefined;
    const root_len = overlay.rootPath().len;
    @memcpy(root_buf[0..root_len], overlay.rootPath());
    const saved_root = root_buf[0..root_len];

    overlay.deinit();

    // Root should no longer exist
    const access_result = std.Io.Dir.accessAbsolute(io, saved_root, .{});
    try testing.expectError(error.FileNotFound, access_result);
}
