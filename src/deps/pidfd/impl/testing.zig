const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const SupervisorFD = types.SupervisorFD;
const Result = types.LinuxResult;

pub inline fn lookupGuestFd(_: linux.pid_t, local_fd: SupervisorFD) !SupervisorFD {
    return local_fd;
}

pub inline fn lookupGuestFdWithRetry(_: linux.pid_t, local_fd: SupervisorFD, _: std.Io) !SupervisorFD {
    return local_fd;
}
