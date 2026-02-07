const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Io = std.Io;
const File = Io.File;

const Self = @This();

// Buffer is entirely in-memory, no disk offload yet
// Add disk buffering if this starts OOMing
stdout_backing: Writer.Allocating,
stderr_backing: Writer.Allocating,
mutex: Io.Mutex = .init,

pub fn init(gpa: Allocator) Self {
    return .{ .stdout_backing = Writer.Allocating.init(gpa), .stderr_backing = Writer.Allocating.init(gpa) };
}

pub fn deinit(self: *Self) void {
    self.stdout_backing.deinit();
    self.stderr_backing.deinit();
}

/// Write data to stdout buffer.
/// Awaits internal mutex
pub fn writeStdout(self: *Self, io: Io, data: []const u8) !void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    try self.stdout_backing.writer.writeAll(data);
}

/// Write data to stderr buffer.
/// Awaits internal mutex.
pub fn writeStderr(self: *Self, io: Io, data: []const u8) !void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    try self.stderr_backing.writer.writeAll(data);
}

/// Drain stdout buffer: returns a copy of accumulated data and clears the buffer.
/// Caller owns the returned slice.
pub fn readStdout(self: *Self, io: Io, allocator: Allocator) ![]u8 {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const data = self.stdout_backing.written();
    const copy = try allocator.dupe(u8, data);
    self.stdout_backing.clearRetainingCapacity();
    return copy;
}

/// Drain stderr buffer: returns a copy of accumulated data and clears the buffer.
/// Caller owns the returned slice.
pub fn readStderr(self: *Self, io: Io, allocator: Allocator) ![]u8 {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const data = self.stderr_backing.written();
    const copy = try allocator.dupe(u8, data);
    self.stderr_backing.clearRetainingCapacity();
    return copy;
}

/// Returns the byte count of stored stdout data.
pub fn stdoutLen(self: *Self, io: Io) usize {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    return self.stdout_backing.written().len;
}

/// Returns the byte count of stored stderr data.
pub fn stderrLen(self: *Self, io: Io) usize {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    return self.stderr_backing.written().len;
}

/// Drain stdout buffer and write contents to the real process stdout.
pub fn flushStdout(self: *Self, io: Io) void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const data = self.stdout_backing.written();
    if (data.len > 0) {
        writeToFile(File.stdout(), io, data);
        self.stdout_backing.clearRetainingCapacity();
    }
}

/// Drain stderr buffer and write contents to the real process stderr.
pub fn flushStderr(self: *Self, io: Io) void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const data = self.stderr_backing.written();
    if (data.len > 0) {
        writeToFile(File.stderr(), io, data);
        self.stderr_backing.clearRetainingCapacity();
    }
}

/// Drain both buffers to their respective destinations.
pub fn flushAll(self: *Self, io: Io) void {
    self.flushStdout(io);
    self.flushStderr(io);
}

fn writeToFile(file: File, io: Io, data: []const u8) void {
    if (comptime builtin.is_test) return;
    var buf: [4096]u8 = undefined;
    var w = file.writerStreaming(io, &buf);
    w.interface.writeAll(data) catch {};
    w.interface.flush() catch {};
}

test "stdout and stderr are independent" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var buf = Self.init(allocator);
    defer buf.deinit();

    try buf.writeStdout(io, "out1\n");
    try buf.writeStderr(io, "err1\n");
    try buf.writeStdout(io, "out2\n");

    try std.testing.expectEqual(10, buf.stdoutLen(io));
    try std.testing.expectEqual(5, buf.stderrLen(io));

    const out = try buf.readStdout(io, allocator);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("out1\nout2\n", out);

    const err = try buf.readStderr(io, allocator);
    defer allocator.free(err);
    try std.testing.expectEqualStrings("err1\n", err);
}

test "drain clears buffer" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var buf = Self.init(allocator);
    defer buf.deinit();

    try buf.writeStdout(io, "hello");
    try std.testing.expectEqual(5, buf.stdoutLen(io));

    const data = try buf.readStdout(io, allocator);
    defer allocator.free(data);
    try std.testing.expectEqualStrings("hello", data);

    try std.testing.expectEqual(0, buf.stdoutLen(io));
}

test "drain returns independent copy" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var buf = Self.init(allocator);
    defer buf.deinit();

    try buf.writeStdout(io, "before");
    const copy = try buf.readStdout(io, allocator);
    defer allocator.free(copy);

    // Write more after draining
    try buf.writeStdout(io, " after");

    // Copy should be unaffected
    try std.testing.expectEqualStrings("before", copy);
}

test "successive drains" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var buf = Self.init(allocator);
    defer buf.deinit();

    try buf.writeStdout(io, "first");
    const d1 = try buf.readStdout(io, allocator);
    defer allocator.free(d1);
    try std.testing.expectEqualStrings("first", d1);

    try buf.writeStdout(io, "second");
    const d2 = try buf.readStdout(io, allocator);
    defer allocator.free(d2);
    try std.testing.expectEqualStrings("second", d2);
}
