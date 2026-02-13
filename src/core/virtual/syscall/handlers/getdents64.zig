const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: getdents64(fd, buf_addr, count)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_addr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    // Passthrough for stdio (kernel will return ENOTDIR)
    if (fd == linux.STDIN_FILENO or fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        return replyContinue(notif.id);
    }

    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);
        
        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("close: EBADF for fd={d}", .{fd});
            return LinuxErr.BADF;
        };
    }
    defer file.unref();

    const max_len = 4096;
    var stack_buf: [max_len]u8 = undefined;
    const capped_count = @min(count, max_len);

    const n: usize = if (file.backingFd()) |backing_fd| blk: {
        // Backends with a kernel FD (passthrough/cow/tmp): forward to kernel
        const rc = linux.getdents64(backing_fd, &stack_buf, capped_count);
        try checkErr(rc, "getdents64 fd={d}", .{fd});
        break :blk rc;
    } else blk: {
        // Proc backend: synthesize directory entries from namespace state
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);
        const caller = try supervisor.guest_threads.get(caller_tid);
        break :blk try file.getdents64(stack_buf[0..capped_count], caller);
    };

    if (n > 0) {
        try memory_bridge.writeSlice(stack_buf[0..n], @intCast(notif.pid), buf_addr);
    }

    logger.log("getdents64: fd={d} returned {d} bytes", .{ fd, n });
    return replySuccess(notif.id, @intCast(n));
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;

test "getdents64 on directory returns entries" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Open /tmp as a real directory FD and wrap in a passthrough File
    const open_rc = linux.openat(linux.AT.FDCWD, "/tmp", .{ .ACCMODE = .RDONLY }, 0);
    try checkErr(open_rc, "test: open /tmp", .{});
    const raw_fd: linux.fd_t = @intCast(open_rc);

    const file = try File.init(allocator, .{ .passthrough = .{ .fd = raw_fd } });
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const vfd = try caller.fd_table.insert(file, .{});

    var result_buf: [1024]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&result_buf),
        .arg2 = result_buf.len,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expect(resp.val > 0);
}

test "getdents64 on non-existent VFD returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "getdents64 with unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid + 1,
        .arg0 = 3,
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}

test "getdents64 on proc /proc/self lists status entry" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Open /proc/self as a proc file and set its opened_path so getdents64 knows the context
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const file = try File.init(allocator, .{ .proc = proc_file });
    try file.setOpenedPath("/proc/self");
    const vfd = try caller.fd_table.insert(file, .{});

    var result_buf: [512]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&result_buf),
        .arg2 = result_buf.len,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expect(resp.val > 0);
}

test "getdents64 on stdio returns replyContinue" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid,
        .arg0 = 0, // stdin
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}