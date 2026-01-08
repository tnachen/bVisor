const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../Supervisor.zig");

const Self = @This();

fd: FD,
buf_ptr: u64,
count: usize,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .buf_ptr = notif.data.arg1,
        .count = @min(@as(usize, @truncate(notif.data.arg2)), 4096),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    logger.log("Emulating read: fd={d} count={d}", .{ self.fd, self.count });

    // Check if FD is tracked by overlay (including redirected stdio)
    if (overlay.hasFD(self.fd)) {
        // FD is in overlay - handle it
    } else if (self.fd >= 0 and self.fd <= 2) {
        // Real stdio (not redirected) - passthrough
        logger.log("read: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    } else {
        // Unknown FD > 2 - return EBADF (full virtualization)
        logger.log("read: EBADF for unknown fd={d}", .{self.fd});
        return .{ .handled = Result.Handled.err(.BADF) };
    }

    // Read from overlay
    var local_buf: [4096]u8 = undefined;
    const bytes_read = overlay.read(self.fd, local_buf[0..self.count]) catch |err| {
        logger.log("read failed: {}", .{err});
        return switch (err) {
            error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
            error.NotOpenForReading => .{ .handled = Result.Handled.err(.BADF) },
            error.Canceled => .{ .handled = Result.Handled.err(.INTR) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    // Write data to child's buffer
    if (bytes_read > 0) {
        try supervisor.mem_bridge.writeSlice(local_buf[0..bytes_read], self.buf_ptr);
    }

    logger.log("read: read {d} bytes from fd={d}", .{ bytes_read, self.fd });
    return .{ .handled = Result.Handled.success(@intCast(bytes_read)) };
}
