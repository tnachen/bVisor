const std = @import("std");
const posix = std.posix;
const OverlayRoot = @import("../../OverlayRoot.zig");

/// Passthrough backend - directly wraps a kernel file descriptor.
/// Used for safe device files like /dev/null, /dev/zero, /dev/urandom.
pub const Passthrough = struct {
    fd: posix.fd_t,

    pub fn open(_: *OverlayRoot, path: []const u8, flags: posix.O, mode: posix.mode_t) !Passthrough {
        const fd = try posix.open(path, flags, mode);
        return .{ .fd = fd };
    }

    pub fn read(self: *Passthrough, buf: []u8) !usize {
        return posix.read(self.fd, buf);
    }

    pub fn write(self: *Passthrough, data: []const u8) !usize {
        return posix.write(self.fd, data);
    }

    pub fn close(self: *Passthrough) void {
        posix.close(self.fd);
    }
};

const testing = std.testing;
const builtin = @import("builtin");

// For testing we use known /dev paths

test "open /dev/null succeeds" {}

test "write to /dev/null succeeds" {}

test "read from /dev/null returns 0 (EOF)" {}

test "read from /dev/zero returns zeros" {}
