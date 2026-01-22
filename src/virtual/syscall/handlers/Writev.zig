const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const KernelFD = types.KernelFD;
const Supervisor = @import("../../../Supervisor.zig");
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const Self = @This();

const MAX_IOV = 16;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const iovec_ptr: u64 = notif.data.arg1;
    const iovec_count: usize = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV);
    var iovecs: [MAX_IOV]posix.iovec_const = undefined;
    var data_buf: [4096]u8 = undefined;
    var data_len: usize = 0;

    // Read iovec array from child memory
    for (0..iovec_count) |i| {
        const iov_addr = iovec_ptr + i * @sizeOf(posix.iovec_const);
        iovecs[i] = memory_bridge.read(posix.iovec_const, @intCast(notif.pid), iov_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
    }

    // Read buffer data from child memory for each iovec (one syscall per iovec)
    for (0..iovec_count) |i| {
        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, data_buf.len - data_len);

        if (buf_len > 0) {
            const dest = data_buf[data_len..][0..buf_len];
            memory_bridge.readSlice(dest, @intCast(notif.pid), buf_ptr) catch {
                return replyErr(notif.id, .FAULT);
            };
            data_len += buf_len;
        }
    }

    const logger = supervisor.logger;
    // TODO: supervisor.fs

    // Only handle stdout = stderr
    const data = data_buf[0..data_len];
    switch (fd) {
        linux.STDOUT_FILENO => {
            var stdout_buffer: [1024]u8 = undefined;
            var stdout_writer = std.Io.File.stdout().writer(supervisor.io, &stdout_buffer);
            const stdout = &stdout_writer.interface;
            stdout.writeAll(data) catch {
                logger.log("writev: error writing to stdout", .{});
                return replyErr(notif.id, .IO);
            };
        },
        linux.STDERR_FILENO => {
            var stderr_buffer: [1024]u8 = undefined;
            var stderr_writer = std.Io.File.stderr().writer(supervisor.io, &stderr_buffer);
            const stderr = &stderr_writer.interface;
            stderr.writeAll(data) catch {
                logger.log("writev: error writing to stderr", .{});
                return replyErr(notif.id, .IO);
            };
        },
        else => {
            // ERIK TODO
            logger.log("writev to non-stdout/stderr fd={d} is not implemented", .{fd});
            return replyErr(notif.id, .PERM);
        },
    }

    return replySuccess(notif.id, @intCast(data_len));
}
