const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Event = @import("../../fs/backend/event.zig").Event;
const Supervisor = @import("../../../Supervisor.zig");
const notif_helpers = @import("../../../seccomp/notif.zig");
const replySuccess = notif_helpers.replySuccess;
const addfd = notif_helpers.addfd;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;
    const allocator = supervisor.allocator;

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    const count: u32 = @truncate(notif.data.arg0);
    const flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg1)));

    const event_fd = try Event.open(count, flags);

    const file = try File.init(allocator, .{ .event = event_fd });
    errdefer file.unref();

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    const caller = try supervisor.guest_threads.get(caller_tid);
    const vfd = try caller.fd_table.insert(file, .{ .cloexec = flags.CLOEXEC });
    errdefer _ = caller.fd_table.remove(vfd);

    try addfd(supervisor.notify_fd, notif.id, event_fd.fd, vfd, flags.CLOEXEC);

    logger.log("eventfd: created vfd={d}", .{vfd});
    return replySuccess(notif.id, vfd);
}
