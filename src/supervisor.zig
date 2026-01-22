const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;
const types = @import("types.zig");
const syscalls = @import("virtual/syscall/syscalls.zig");
const SupervisorFD = types.SupervisorFD;
const Result = types.LinuxResult;
const Logger = types.Logger;
const Procs = @import("virtual/proc/Procs.zig");
const Cow = @import("virtual/fs/Cow.zig");
const Tmp = @import("virtual/fs/Tmp.zig");
const Allocator = std.mem.Allocator;

const Self = @This();

allocator: Allocator,
io: Io,
init_guest_pid: linux.pid_t,
notify_fd: SupervisorFD,
logger: Logger,

// All procs starting from the initial guest proc are assigned a virtual PID and tracked via guest_procs
// All pros track their own virtual namespaces and file descriptors
guest_procs: Procs,

// COW filesystem for sandbox isolation
cow: Cow,
// Private /tmp for sandbox isolation
tmp: Tmp,

pub fn init(allocator: Allocator, io: Io, notify_fd: SupervisorFD, init_guest_pid: linux.pid_t) !Self {
    const logger = Logger.init(.supervisor);
    var guest_procs = Procs.init(allocator);
    errdefer guest_procs.deinit();
    _ = try guest_procs.handleInitialProcess(init_guest_pid); // ERIK TODO: "handle" to "register"

    // Generate shared UID for all sandbox directories
    const uid = Cow.generateUid(); // ERIK TODO: move impl into here, why have it in cow? dumb

    // ERIK TODO: merge COW and TMP into a VFS struct, single init and deinit
    var cow = try Cow.init(io, uid);
    errdefer cow.deinit(io);
    var tmp = try Tmp.init(io, uid);
    errdefer tmp.deinit(io);

    return .{
        .allocator = allocator,
        .io = io,
        .init_guest_pid = init_guest_pid,
        .notify_fd = notify_fd,
        .logger = logger,
        .guest_procs = guest_procs,
        .cow = cow,
        .tmp = tmp,
    };
}

pub fn deinit(self: *Self) void {
    if (self.notify_fd >= 0) {
        posix.close(self.notify_fd);
    }
    self.guest_procs.deinit();
    self.cow.deinit(self.io);
    self.tmp.deinit(self.io);
}

/// Main notification loop. Reads syscall notifications from the kernel,
pub fn run(self: *Self) !void {
    // Supervisor handles syscalls in a single blocking thread. 80/20 solution for now, will rethink once we benchmark
    while (true) {
        // Receive syscall notification from kernel
        const notif = try self.recv() orelse return;
        const resp = syscalls.handle(notif, self);
        try self.send(resp);
    }
}

fn recv(self: Self) !?linux.SECCOMP.notif {
    var notif: linux.SECCOMP.notif = std.mem.zeroes(linux.SECCOMP.notif);
    const recv_result = linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&notif));
    switch (Result(usize).from(recv_result)) {
        .Ok => return notif,
        .Error => |err| switch (err) {
            .NOENT => {
                self.logger.log("Guest exited, stopping notification handler", .{});
                return null;
            },
            else => |_| return posix.unexpectedErrno(err),
        },
    }
}

fn send(self: Self, resp: linux.SECCOMP.notif_resp) !void {
    const send_result = linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&resp));
    switch (Result(usize).from(send_result)) {
        .Ok => {},
        .Error => |err| switch (err) {
            .NOENT => {
                // Process exited before we could respond - this is fine
                self.logger.log("Process exited before response could be sent", .{});
            },
            else => return posix.unexpectedErrno(err),
        },
    }
}
