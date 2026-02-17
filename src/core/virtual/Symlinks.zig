const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("../linux_error.zig").checkErr;

const Self = @This();

const dir = "/.b";
const charset = "0123456789abcdefghijklmnopqrstuvwxyz_";
const charset_len = charset.len; // 37
const code_len = 3;
pub const max_entries: u32 = charset_len * charset_len * charset_len; // 50,653
pub const path_len = dir.len + 1 + code_len; // "/.b/" + "XXX" = 7

counter: std.atomic.Value(u32),

pub fn init() Self {
    return .{
        .counter = std.atomic.Value(u32).init(0),
    };
}

pub fn deinit(_: *Self) void {
    // Remove /.b if empty (succeeds only if no other sandbox is using it)
    _ = linux.unlinkat(linux.AT.FDCWD, dir, linux.AT.REMOVEDIR);
}

fn ensureDir() void {
    _ = linux.mkdirat(linux.AT.FDCWD, dir, 0o777);
}

fn encodeIndex(idx: u32, buf: *[code_len]u8) void {
    var n = idx;
    var i: usize = code_len;
    while (i > 0) {
        i -= 1;
        buf[i] = charset[n % charset_len];
        n /= charset_len;
    }
}

fn formatPath(idx: u32, buf: *[path_len + 1]u8) []const u8 {
    @memcpy(buf[0..dir.len], dir);
    buf[dir.len] = '/';
    var code: [code_len]u8 = undefined;
    encodeIndex(idx, &code);
    @memcpy(buf[dir.len + 1 ..][0..code_len], &code);
    buf[path_len] = 0;
    return buf[0..path_len];
}

/// Creates a symlink at a short path (/.b/XXX) pointing to `target`.
/// `original_path_len` is the guest's original path length; the symlink must fit within it.
/// Returns the symlink path as a slice of `out_buf`.
/// Probes for a free slot if another sandbox has claimed the current index (EEXIST).
pub fn create(self: *Self, target: []const u8, original_path_len: usize, out_buf: *[path_len + 1]u8) ![]const u8 {
    if (path_len > original_path_len) return error.PERM;

    ensureDir();

    var target_buf: [513]u8 = undefined;
    if (target.len > 512) return error.NAMETOOLONG;
    @memcpy(target_buf[0..target.len], target);
    target_buf[target.len] = 0;

    while (true) {
        const idx = self.counter.fetchAdd(1, .monotonic) % max_entries;

        _ = formatPath(idx, out_buf);

        const rc = linux.symlinkat(
            target_buf[0..target.len :0],
            linux.AT.FDCWD,
            out_buf[0..path_len :0],
        );
        checkErr(rc, "Symlinks.create", .{}) catch |err| {
            if (err == error.EXIST) continue;
            return err;
        };

        return out_buf[0..path_len];
    }
}

const testing = std.testing;

test "encodeIndex produces base-37 encoding" {
    var buf: [code_len]u8 = undefined;
    encodeIndex(0, &buf);
    try testing.expectEqualStrings("000", &buf);

    encodeIndex(1, &buf);
    try testing.expectEqualStrings("001", &buf);

    encodeIndex(36, &buf);
    try testing.expectEqualStrings("00_", &buf);

    encodeIndex(37, &buf);
    try testing.expectEqualStrings("010", &buf);
}

test "formatPath produces /.b/XXX" {
    var buf: [path_len + 1]u8 = undefined;
    const p = formatPath(0, &buf);
    try testing.expectEqualStrings("/.b/000", p);
}

test "create returns EPERM when original path shorter than 7" {
    var s = Self.init();
    defer s.deinit();

    var buf: [path_len + 1]u8 = undefined;
    try testing.expectError(error.PERM, s.create("/bin/sh", 6, &buf));
}

test "create skips EEXIST and advances to next slot" {
    var s1 = Self.init();
    defer s1.deinit();
    var s2 = Self.init();
    defer s2.deinit();

    // s1 claims slot 0
    var buf1: [path_len + 1]u8 = undefined;
    const p1 = try s1.create("/bin/sh", 256, &buf1);
    defer _ = linux.unlinkat(linux.AT.FDCWD, buf1[0..path_len :0], 0);
    try testing.expectEqualStrings("/.b/000", p1);

    // s2 also starts at 0, hits EEXIST, advances to 1
    var buf2: [path_len + 1]u8 = undefined;
    const p2 = try s2.create("/bin/sh", 256, &buf2);
    defer _ = linux.unlinkat(linux.AT.FDCWD, buf2[0..path_len :0], 0);
    try testing.expectEqualStrings("/.b/001", p2);
}
