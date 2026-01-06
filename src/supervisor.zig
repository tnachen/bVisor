const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("types.zig");
const syscall = @import("syscall.zig");
const Notification = @import("Notification.zig");
const FD = types.FD;
const MemoryBridge = types.MemoryBridge;
const Result = types.LinuxResult;
const Logger = types.Logger;

const Self = @This();

notify_fd: FD,
logger: Logger,
mem_bridge: MemoryBridge,

pub fn init(notify_fd: FD, child_pid: linux.pid_t) Self {
    const mem_bridge = MemoryBridge.init(child_pid);
    const logger = Logger.init(.supervisor);
    return .{ .notify_fd = notify_fd, .logger = logger, .mem_bridge = mem_bridge };
}

pub fn deinit(self: @This()) void {
    posix.close(self.notify_fd);
}

/// Main notification loop. Reads syscall notifications from the kernel,
pub fn run(self: @This()) !void {
    while (true) {
        // Receive syscall notification from kernel
        const notif = try self.recv() orelse return;
        const notification = try Notification.from_notif(self.mem_bridge, notif);

        // Handle (or prepare passthrough resp)
        const response = try notification.handle(self.mem_bridge, self.logger);

        // Reply to kernel
        try self.send(response.to_notif_resp());
    }
}

fn recv(self: Self) !?linux.SECCOMP.notif {
    var notif: linux.SECCOMP.notif = std.mem.zeroes(linux.SECCOMP.notif);
    const recv_result = linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&notif));
    switch (Result(usize).from(recv_result)) {
        .Ok => return notif,
        .Error => |err| switch (err) {
            .NOENT => {
                self.logger.log("Child exited, stopping notification handler", .{});
                return null;
            },
            else => |_| return posix.unexpectedErrno(err),
        },
    }
}

fn send(self: Self, resp: linux.SECCOMP.notif_resp) !void {
    _ = try Result(usize).from(
        linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&resp)),
    ).unwrap();
}
