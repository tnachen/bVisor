const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;

const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// exit_group exits all threads in a thread group
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    supervisor.mutex.lock();
    defer supervisor.mutex.unlock();

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        std.log.err("exit_group: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyContinue(notif.id);
    };
    std.debug.assert(caller.tid == caller_tid);

    // Send SIGKILL for any Thread-s in the caller's ThreadGroup
    var tg_iter = caller.thread_group.threads.iterator();
    while (tg_iter.next()) |entry| {
        const thread = entry.value_ptr.*;
        if (thread != caller) {
            std.posix.kill(thread.tid, .KILL) catch |err| {
                std.log.debug("exit_group: posix.kill({d}): {}", .{ thread.tid, err });
            };
        }
    }

    // Clean up virtual Thread entry before kernel handles the exit
    // Ignore errors - Thread may have already been cleaned up
    supervisor.guest_threads.handleThreadExit(caller_tid) catch {};

    // Let kernel execute the actual exit_group syscall
    return replyContinue(notif.id);
}
