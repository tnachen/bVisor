const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("../linux_error.zig").checkErr;

const Self = @This();

// common base of symlink path
const base = "/tmp/.b";
// prefix length of UID to use
const prefix_len = 4;
// ceil(log10(2) * 32)
const max_counter_digits = 10;
pub const max_path_len = base.len + prefix_len + max_counter_digits;

// prefix of sandbox UID
uid_prefix: [prefix_len]u8,
counter: std.atomic.Value(u32),

pub fn init(uid: [16]u8) Self {
    return .{
        .uid_prefix = uid[0..prefix_len].*,
        .counter = std.atomic.Value(u32).init(0),
    };
}

pub fn deinit(self: *Self) void {
    const count = self.counter.load(.monotonic);
    for (0..count) |i| {
        var buf: [max_path_len + 1]u8 = undefined;
        // path = `/tmp/.b<uid_prefix><counter>`
        const path = std.fmt.bufPrint(&buf, base ++ "{s}{d}", .{ &self.uid_prefix, i }) catch continue;
        buf[path.len] = 0;

        // unlinkat syscall
        _ = linux.unlinkat(@bitCast(@as(i32, linux.AT.FDCWD)), buf[0..path.len :0], 0);
    }
}

/// Creates a symlink at a short path pointing to `target` (the real overlay path).
/// `original_path_len` is the guest's original path length; the symlink path must fit within it.
/// Returns the symlink path as a slice of `out_buf`
pub fn create(self: *Self, target: []const u8, original_path_len: usize, out_buf: *[max_path_len + 1]u8) ![]const u8 {
    const idx = self.counter.fetchAdd(1, .monotonic);
    const symlink_path = std.fmt.bufPrint(out_buf, base ++ "{s}{d}", .{ &self.uid_prefix, idx }) catch return error.NAMETOOLONG;

    // Should not write more bytes into guest's memory than what was originally allocated
    if (symlink_path.len > original_path_len) {
        return error.PERM;
    }

    // Zero-terminate for linux syscall
    out_buf[symlink_path.len] = 0;

    var target_buf: [513]u8 = undefined;
    if (target.len > 512) return error.NAMETOOLONG;
    @memcpy(target_buf[0..target.len], target);
    target_buf[target.len] = 0;

    // Symlinkat syscall
    const rc = linux.symlinkat(
        target_buf[0..target.len :0],
        @bitCast(@as(i32, linux.AT.FDCWD)),
        out_buf[0..symlink_path.len :0],
    );
    try checkErr(rc, "Symlinks.create", .{});

    return symlink_path;
}

const testing = std.testing;

test "init sets uid_prefix from first 4 chars" {
    const uid: [16]u8 = "abcdef0123456789".*;
    const s = Self.init(uid);
    try testing.expectEqualStrings("abcd", &s.uid_prefix);
}

test "create generates sequential paths" {
    const uid: [16]u8 = "symlsymlsyml0001".*;
    var s = Self.init(uid);
    defer s.deinit();

    var buf1: [max_path_len + 1]u8 = undefined;
    const path1 = try s.create("/bin/sh", 256, &buf1);
    try testing.expectEqualStrings("/tmp/.bsyml0", path1);

    var buf2: [max_path_len + 1]u8 = undefined;
    const path2 = try s.create("/bin/sh", 256, &buf2);
    try testing.expectEqualStrings("/tmp/.bsyml1", path2);
}

test "create returns EPERM when symlink path longer than original" {
    const uid: [16]u8 = "symlsymlsyml0002".*;
    var s = Self.init(uid);
    defer s.deinit();

    var buf: [max_path_len + 1]u8 = undefined;
    // "/tmp/.bsyml0" is 12 chars, so original_path_len=5 should fail
    try testing.expectError(error.PERM, s.create("/some/target", 5, &buf));
}

test "deinit cleans up created symlinks" {
    const uid: [16]u8 = "symlsymlsyml0003".*;
    var s = Self.init(uid);

    var buf: [max_path_len + 1]u8 = undefined;
    _ = try s.create("/bin/sh", 256, &buf);

    try testing.expectEqual(1, s.counter.load(.monotonic));

    s.deinit();
    // Symlink should be removed; verify by trying to access it
    const access_result = std.Io.Dir.accessAbsolute(testing.io, "/tmp/.bsyml0", .{});
    try testing.expectError(error.FileNotFound, access_result);
}
