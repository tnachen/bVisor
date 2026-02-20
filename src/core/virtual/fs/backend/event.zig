const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("../../../linux_error.zig").checkErr;

fn sysRead(fd: linux.fd_t, buf: []u8) !usize {
    const rc = linux.read(fd, buf.ptr, buf.len);
    try checkErr(rc, "event.sysRead", .{});
    return rc;
}

fn sysWrite(fd: linux.fd_t, data: []const u8) !usize {
    const rc = linux.write(fd, data.ptr, data.len);
    try checkErr(rc, "event.sysWrite", .{});
    return rc;
}

/// Event backend - same as passthrough but no path and restricted api surface
/// Used by eventfd syscall
pub const Event = struct {
    fd: linux.fd_t,

    pub fn open(count: u32, flags: u32) !Event {
        const fd = linux.eventfd(count, flags);
        try checkErr(fd, "event.open", .{});
        return .{ .fd = @intCast(fd) };
    }

    pub fn read(self: *Event, buf: []u8) !usize {
        return sysRead(self.fd, buf);
    }

    pub fn write(self: *Event, data: []const u8) !usize {
        return sysWrite(self.fd, data);
    }

    // Ignores EBADF — tests create Files with fake fds that were never opened
    pub fn close(self: *Event) void {
        _ = linux.close(self.fd);
    }

    // eventFD doesn't support the following apis
    pub fn statx(_: *Event) !linux.Statx {
        return error.INVAL;
    }

    pub fn statxByPath(_: []const u8) !linux.Statx {
        return error.INVAL;
    }

    pub fn lseek(_: *Event, _: i64, _: u32) !i64 {
        return error.INVAL;
    }

    pub fn ioctl(_: *Event, _: linux.IOCTL.Request, _: usize) !usize {
        return error.INVAL;
    }

    pub fn connect(_: *Event, _: [*]const u8, _: linux.socklen_t) !void {
        return error.INVAL;
    }

    pub fn getdents64(_: *Event, _: []u8) !usize {
        return error.INVAL;
    }

    pub fn shutdown(_: *Event, _: i32) !void {
        return error.INVAL;
    }

    pub fn recvFrom(_: *Event, _: []u8, _: u32, _: ?[*]u8, _: ?*linux.socklen_t) !usize {
        return error.INVAL;
    }

    pub fn sendTo(_: *Event, _: []const u8, _: u32, _: ?[*]const u8, _: linux.socklen_t) !usize {
        return error.INVAL;
    }
};
