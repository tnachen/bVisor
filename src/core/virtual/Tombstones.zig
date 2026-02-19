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

/// Remove all tombstones that are children of `dir_path`.
/// Called on rmdir to prevent orphaned child tombstones from persisting
/// after the parent directory is removed.
pub fn removeChildren(self: *Self, dir_path: []const u8) void {
    var buf: [513]u8 = undefined;
    const prefix = if (std.mem.eql(u8, dir_path, "/"))
        "/"
    else blk: {
        if (dir_path.len + 1 > buf.len) return;
        @memcpy(buf[0..dir_path.len], dir_path);
        buf[dir_path.len] = '/';
        break :blk buf[0 .. dir_path.len + 1];
    };

    var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
    defer to_remove.deinit(self.allocator);

    var iter = self.map.iterator();
    while (iter.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, prefix) and entry.key_ptr.*.len > prefix.len) {
            to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
        }
    }

    for (to_remove.items) |key| {
        if (self.map.fetchRemove(key)) |entry| {
            self.allocator.free(entry.key);
        }
    }
}

pub fn isTombstoned(self: *const Self, path: []const u8) bool {
    return self.map.contains(path);
}

/// Check if any ancestor directory of `path` is tombstoned.
pub fn isAncestorTombstoned(self: *const Self, path: []const u8) bool {
    var current = path;
    while (std.fs.path.dirname(current)) |parent| {
        if (self.map.contains(parent)) return true;
        if (std.mem.eql(u8, parent, "/")) break;
        current = parent;
    }
    return false;
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

test "removeChildren clears child tombstones but not the parent" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/home/user");
    try ts.add("/home/user/file.txt");
    try ts.add("/home/user/docs/readme.md");
    try ts.add("/home/other");

    ts.removeChildren("/home/user");

    try testing.expect(ts.isTombstoned("/home/user"));
    try testing.expect(!ts.isTombstoned("/home/user/file.txt"));
    try testing.expect(!ts.isTombstoned("/home/user/docs/readme.md"));
    try testing.expect(ts.isTombstoned("/home/other"));
}

test "isAncestorTombstoned detects tombstoned parent" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/home/user");

    try testing.expect(ts.isAncestorTombstoned("/home/user/file.txt"));
    try testing.expect(ts.isAncestorTombstoned("/home/user/docs/readme.md"));
    try testing.expect(!ts.isAncestorTombstoned("/home/user"));
    try testing.expect(!ts.isAncestorTombstoned("/home/other"));
    try testing.expect(!ts.isAncestorTombstoned("/etc/passwd"));
}

test "isAncestorTombstoned detects tombstoned grandparent" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/home");

    try testing.expect(ts.isAncestorTombstoned("/home/user/file.txt"));
    try testing.expect(ts.isAncestorTombstoned("/home/user"));
    try testing.expect(!ts.isAncestorTombstoned("/home"));
}

test "isAncestorTombstoned with root tombstone" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/");

    try testing.expect(ts.isAncestorTombstoned("/anything"));
    try testing.expect(ts.isAncestorTombstoned("/deep/nested/path"));
}

test "removeChildren on path with no children is a no-op" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd");
    ts.removeChildren("/etc/passwd");
    try testing.expect(ts.isTombstoned("/etc/passwd"));
}
