const std = @import("std");

const Self = @This();

map: std.StringHashMapUnmanaged(void),
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Self {
    return .{
        .map = .empty,
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    var iter = self.map.iterator();
    while (iter.next()) |entry| {
        self.allocator.free(entry.key_ptr.*);
    }
    self.map.deinit(self.allocator);
}

/// Record a path as deleted.
pub fn add(self: *Self, path: []const u8) !void {
    const gop = try self.map.getOrPut(self.allocator, path);
    if (!gop.found_existing) {
        errdefer _ = self.map.remove(path);
        gop.key_ptr.* = try self.allocator.dupe(u8, path);
    }
}

/// Remove a tombstone (e.g., when a file is recreated via O_CREAT).
pub fn remove(self: *Self, path: []const u8) void {
    if (self.map.fetchRemove(path)) |entry| {
        self.allocator.free(entry.key);
    }
}

pub fn isTombstoned(self: *const Self, path: []const u8) bool {
    return self.map.contains(path);
}

/// Check if a direct child of `dir_path` is tombstoned.
/// Used by getdents64 to filter individual directory entries.
pub fn isChildTombstoned(self: *const Self, dir_path: []const u8, child_name: []const u8) bool {
    var buf: [512]u8 = undefined;
    const child_path = if (std.mem.eql(u8, dir_path, "/"))
        std.fmt.bufPrint(&buf, "/{s}", .{child_name}) catch return false
    else
        std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir_path, child_name }) catch return false;
    return self.isTombstoned(child_path);
}

const testing = std.testing;

test "empty tombstones: nothing is tombstoned" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try testing.expect(!ts.isTombstoned("/etc/passwd"));
    try testing.expect(!ts.isTombstoned("/tmp/foo"));
}

test "add tombstone: exact path is tombstoned" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd");

    try testing.expect(ts.isTombstoned("/etc/passwd"));
    try testing.expect(!ts.isTombstoned("/etc/shadow"));
    try testing.expect(!ts.isTombstoned("/etc"));
}

test "tombstone does not affect children or parents" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/usr/local");

    try testing.expect(ts.isTombstoned("/usr/local"));
    try testing.expect(!ts.isTombstoned("/usr/local/bin"));
    try testing.expect(!ts.isTombstoned("/usr"));
}

test "remove tombstone: path is no longer tombstoned" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd");
    try testing.expect(ts.isTombstoned("/etc/passwd"));

    ts.remove("/etc/passwd");
    try testing.expect(!ts.isTombstoned("/etc/passwd"));
}

test "remove non-existent tombstone is no-op" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    ts.remove("/nonexistent");
}

test "isChildTombstoned checks direct children" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd");

    try testing.expect(ts.isChildTombstoned("/etc", "passwd"));
    try testing.expect(!ts.isChildTombstoned("/etc", "shadow"));
}

test "multiple tombstones coexist" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd");
    try ts.add("/var/log");

    try testing.expect(ts.isTombstoned("/etc/passwd"));
    try testing.expect(ts.isTombstoned("/var/log"));
    try testing.expect(!ts.isTombstoned("/etc/shadow"));
    try testing.expect(!ts.isTombstoned("/var/run"));
}

test "re-adding same path is idempotent" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd");
    try ts.add("/etc/passwd");

    try testing.expect(ts.isTombstoned("/etc/passwd"));

    ts.remove("/etc/passwd");
    try testing.expect(!ts.isTombstoned("/etc/passwd"));
}
