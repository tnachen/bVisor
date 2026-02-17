const std = @import("std");

const Self = @This();

pub const Kind = enum { file, dir };

map: std.StringHashMapUnmanaged(Kind),
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
/// Use `.dir` for directories to recursively tombstone all contents.
pub fn add(self: *Self, path: []const u8, kind: Kind) !void {
    const gop = try self.map.getOrPut(self.allocator, path);
    if (!gop.found_existing) {
        gop.key_ptr.* = try self.allocator.dupe(u8, path);
    }
    gop.value_ptr.* = kind;
}

/// Remove a tombstone (e.g., when a file is recreated via O_CREAT).
pub fn remove(self: *Self, path: []const u8) void {
    if (self.map.fetchRemove(path)) |entry| {
        self.allocator.free(entry.key);
    }
}

/// Check if a path is tombstoned, either directly or via an ancestor dir tombstone.
pub fn isTombstoned(self: *const Self, path: []const u8) bool {
    if (self.map.get(path) != null) return true;

    // Walk ancestors: if any ancestor directory is tombstoned, this path is too
    var end: usize = path.len;
    while (end > 0) {
        end -= 1;
        if (path[end] == '/') {
            const ancestor = if (end == 0) "/" else path[0..end];
            if (self.map.get(ancestor)) |kind| {
                if (kind == .dir) return true;
            }
        }
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

test "add file tombstone: exact path is tombstoned" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd", .file);

    try testing.expect(ts.isTombstoned("/etc/passwd"));
    try testing.expect(!ts.isTombstoned("/etc/shadow"));
    try testing.expect(!ts.isTombstoned("/etc"));
}

test "add dir tombstone: children are recursively tombstoned" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/usr/local", .dir);

    try testing.expect(ts.isTombstoned("/usr/local"));
    try testing.expect(ts.isTombstoned("/usr/local/bin"));
    try testing.expect(ts.isTombstoned("/usr/local/bin/python"));
    try testing.expect(!ts.isTombstoned("/usr/bin"));
    try testing.expect(!ts.isTombstoned("/usr"));
}

test "remove tombstone: path is no longer tombstoned" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd", .file);
    try testing.expect(ts.isTombstoned("/etc/passwd"));

    ts.remove("/etc/passwd");
    try testing.expect(!ts.isTombstoned("/etc/passwd"));
}

test "remove non-existent tombstone is no-op" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    ts.remove("/nonexistent");
}

test "dir tombstone: removing parent unblocks children" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/usr", .dir);
    try testing.expect(ts.isTombstoned("/usr/bin/ls"));

    ts.remove("/usr");
    try testing.expect(!ts.isTombstoned("/usr/bin/ls"));
}

test "file tombstone does not affect children" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc", .file);

    try testing.expect(ts.isTombstoned("/etc"));
    try testing.expect(!ts.isTombstoned("/etc/passwd"));
}

test "upgrade file tombstone to dir" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/usr", .file);
    try testing.expect(!ts.isTombstoned("/usr/bin"));

    try ts.add("/usr", .dir);
    try testing.expect(ts.isTombstoned("/usr/bin"));
}

test "isChildTombstoned checks direct children" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd", .file);

    try testing.expect(ts.isChildTombstoned("/etc", "passwd"));
    try testing.expect(!ts.isChildTombstoned("/etc", "shadow"));
}

test "isChildTombstoned respects dir tombstones" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/usr/local", .dir);

    try testing.expect(ts.isChildTombstoned("/usr", "local"));
    try testing.expect(!ts.isChildTombstoned("/usr", "bin"));
}

test "root dir tombstone blocks everything" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/", .dir);
    try testing.expect(ts.isTombstoned("/anything"));
    try testing.expect(ts.isTombstoned("/deep/nested/path"));
}

test "multiple tombstones coexist" {
    var ts = Self.init(testing.allocator);
    defer ts.deinit();

    try ts.add("/etc/passwd", .file);
    try ts.add("/var/log", .dir);

    try testing.expect(ts.isTombstoned("/etc/passwd"));
    try testing.expect(ts.isTombstoned("/var/log/syslog"));
    try testing.expect(!ts.isTombstoned("/etc/shadow"));
    try testing.expect(!ts.isTombstoned("/var/run"));
}
