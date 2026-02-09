const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Io = std.Io;
const File = Io.File;

const Self = @This();

// Buffer is entirely in-memory, no disk offload yet
// Add disk buffering if this starts OOMing
backing: Writer.Allocating,
mutex: Io.Mutex = .init,

pub fn init(gpa: Allocator) Self {
    return .{ .backing = Writer.Allocating.init(gpa) };
}

pub fn deinit(self: *Self) void {
    self.backing.deinit();
}

/// Write data to stdout buffer.
/// Awaits internal mutex
pub fn write(self: *Self, io: Io, data: []const u8) !void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    try self.backing.writer.writeAll(data);
}

/// Drain stdout buffer: returns a copy of accumulated data and clears the buffer.
/// Caller owns the returned slice.
pub fn read(self: *Self, io: Io, allocator: Allocator) ![]u8 {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const data = self.backing.written();
    const copy = try allocator.dupe(u8, data);
    self.backing.clearRetainingCapacity();
    return copy;
}

pub fn len(self: *Self, io: Io) usize {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    return self.backing.written().len;
}

/// Drain buffer to its respective destination
pub fn flush(self: *Self, io: Io, file: File) void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const data = self.backing.written();
    var w = file.writerStreaming(io, &data);
    w.interface.writeAll(data) catch {};
    w.interface.flush() catch {};
}
