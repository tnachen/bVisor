const std = @import("std");
const Allocator = std.mem.Allocator;
const Procs = @import("Procs.zig");

pub const KernelPID = Procs.KernelPID;
pub const CloneFlags = Procs.CloneFlags;

const Self = @This();

pending: std.AutoHashMapUnmanaged(KernelPID, CloneFlags) = .empty,
allocator: Allocator,

pub fn init(allocator: Allocator) Self {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Self) void {
    self.pending.deinit(self.allocator);
}

pub fn append(self: *Self, parent_pid: KernelPID, flags: CloneFlags) !void {
    try self.pending.put(self.allocator, parent_pid, flags);
}

pub fn remove(self: *Self, parent_pid: KernelPID) ?CloneFlags {
    const kv = self.pending.fetchRemove(parent_pid) orelse return null;
    return kv.value;
}

const testing = std.testing;

test "append and remove" {
    var pc = Self.init(testing.allocator);
    defer pc.deinit();

    const flags = CloneFlags.from(123);
    try pc.append(100, flags);

    const removed = pc.remove(100);
    try testing.expect(removed != null);
    try testing.expectEqual(@as(u64, 123), removed.?.raw);
}

test "remove returns null for unknown" {
    var pc = Self.init(testing.allocator);
    defer pc.deinit();

    const removed = pc.remove(999);
    try testing.expect(removed == null);
}
