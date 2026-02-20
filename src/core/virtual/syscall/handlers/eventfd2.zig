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
    const flags: u32 = @truncate(notif.data.arg1);
    const cloexec = flags & linux.EFD.CLOEXEC != 0;

    const event_fd = try Event.open(count, flags);

    const file = try File.init(allocator, .{ .event = event_fd });
    errdefer file.unref();

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    const caller = try supervisor.guest_threads.get(caller_tid);
    const vfd = try caller.fd_table.insert(file, .{ .cloexec = cloexec });
    errdefer _ = caller.fd_table.remove(vfd);

    try addfd(supervisor.notify_fd, notif.id, event_fd.fd, vfd, cloexec);

    logger.log("eventfd: created vfd={d}", .{vfd});
    return replySuccess(notif.id, vfd);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

test "eventfd2 creates a virtual fd" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.eventfd2, .{
        .pid = init_tid,
        .arg0 = 0,
        .arg1 = 0,
    });

    const resp = try handle(notif, &supervisor);
    const vfd: i32 = @intCast(resp.val);
    try testing.expect(vfd >= 3);

    // Verify the FdTable contains the returned vfd with .event backend
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const file_ref = caller.fd_table.get_ref(vfd);
    defer if (file_ref) |f| f.unref();
    try testing.expect(file_ref != null);
    try testing.expectEqual(File.BackendType.event, std.meta.activeTag(file_ref.?.backend));
}

test "eventfd2 with O_CLOEXEC sets cloexec flag" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.eventfd2, .{
        .pid = init_tid,
        .arg0 = 0,
        .arg1 = linux.EFD.CLOEXEC,
    });

    const resp = try handle(notif, &supervisor);
    const vfd: i32 = @intCast(resp.val);

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    try testing.expect(caller.fd_table.getCloexec(vfd));
}

test "eventfd2 unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.eventfd2, .{
        .pid = 999,
        .arg0 = 0,
        .arg1 = 0,
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}
