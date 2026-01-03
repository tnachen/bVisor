const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

// File Descriptor
const FD = i32;

pub fn main() !void {
    // Create socket pair for child and supervisor
    // To allow inter-process communication
    const socket_pair: [2]FD = try posix.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM,
        0,
    );
    const child_sock: FD, const supervisor_sock: FD = socket_pair;

    // Fork into both subprocesses
    const fork_result = try std.posix.fork();
    if (fork_result == 0) {
        // Child process
        posix.close(supervisor_sock);
        try child_process(child_sock);
        std.debug.print("Child process exiting\n", .{});
    } else {
        // Supervisor process
        posix.close(child_sock);

        // fork_result is the child PID, needed for looking up the notify FD
        const child_pid: linux.pid_t = fork_result;
        try supervisor_process(supervisor_sock, child_pid);

        std.debug.print("Supervisor process exiting\n", .{});
    }
}

const BPFInstruction = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const BPFFilterProgram = extern struct {
    len: u16,
    filter: [*]const BPFInstruction,
};

fn child_process(socket: FD) !void {
    std.debug.print("Child process starting\n", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Before starting seccomp, there's a chicken-and-egg issue
    // The supervisor needs seccomp's FD to listen on
    // But we can't send that FD across the socket once seccomp is running
    // since that .write command to the socket would get blocked

    // To get around this, we predict the FD that seccomp will use
    // and send it on the socket before starting seccomp

    // Posix.dup(0) returns the lowest available fd, which we immediately close
    const next_fd: FD = try posix.dup(0);
    posix.close(next_fd);

    // Send to supervisor then close socket
    var fd_bytes: [4]u8 = undefined;
    std.mem.writeInt(FD, &fd_bytes, next_fd, .little);
    _ = try posix.write(socket, &fd_bytes);
    // posix.close(socket);

    // ===== SECCOMP SETUP =====

    // Set "No New Privileges" mode to prevent this process (and children)
    // from re-elevating their permissions. Required by seccomp.
    _ = try posix.prctl(posix.PR.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });

    // Write a BPF program that instructs the kernel to intercept all syscalls
    // and trigger USER_NOTIF
    var instructions = [_]BPFInstruction{
        .{ .code = linux.BPF.RET | linux.BPF.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.USER_NOTIF },
    };
    var prog = BPFFilterProgram{
        .len = instructions.len,
        .filter = &instructions,
    };

    // Install program using seccomp
    const notify_fd: FD = try Result(FD).from(
        linux.seccomp(
            linux.SECCOMP.SET_MODE_FILTER,
            linux.SECCOMP.FILTER_FLAG.NEW_LISTENER,
            @ptrCast(&prog),
        ),
    ).unwrap();

    // Verify prediction was correct
    if (notify_fd != next_fd) {
        // Prediction failed - exit
        // Can't print, since seccomp is running without a supervisor listening
        return error.PredictionFailed;
    }

    // Now we just run some other process!
    // Shell out to bash with cmd in the future
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        std.debug.print("Child process: {}\n", .{i});
        try io.sleep(std.Io.Duration.fromMilliseconds(500), .awake);
    }
    std.debug.print("Child done!\n", .{});
}

fn Result(comptime T: type) type {
    return union(enum) {
        Ok: T,
        Error: linux.E,

        const Self = @This();

        fn from(result: usize) Self {
            return switch (linux.errno(result)) {
                .SUCCESS => Self{ .Ok = @intCast(result) },
                else => Self{ .Error = linux.errno(result) },
            };
        }

        /// Returns inner value, or throws a general error
        /// If specific error types are needed, prefer to switch on Result then switch on Error branch
        fn unwrap(self: Self) !T {
            return switch (self) {
                .Ok => |value| value,
                .Error => |_| error.SyscallFailed, // Some general error
            };
        }
    };
}

fn supervisor_process(socket: FD, child_pid: linux.pid_t) !void {
    std.debug.print("Supervisor process starting\n", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // ===== Dereferencing notify FD =====
    // The child sends its process-local notify FD across the socket
    // We use its own PID + FD to look up the actual FD

    var child_notify_fd_bytes: [4]u8 = undefined;
    const bytes_read = try posix.read(socket, &child_notify_fd_bytes);
    if (bytes_read != 4) {
        std.debug.print("failed to read fd from socket\n", .{});
        return error.ReadFailed;
    }
    const child_notify_fd: FD = std.mem.readInt(i32, &child_notify_fd_bytes, .little);

    // Use child PID to look up its FD table
    const child_fd_table: FD = try Result(FD).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    // Since notify FD was sent eagerly, poll child's FD table until FD is visible
    // Otherwise we'd have race condition
    var notify_fd: FD = undefined;
    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        const result = linux.pidfd_getfd(child_fd_table, child_notify_fd, 0);
        switch (Result(FD).from(result)) {
            .Ok => |value| {
                notify_fd = value;
                break;
            },
            .Error => |err| switch (err) {
                .BADF => {
                    // FD doesn't exist yet in child - retry
                    try io.sleep(std.Io.Duration.fromMilliseconds(10), .awake);
                    continue;
                },
                else => |_| return posix.unexpectedErrno(err),
            },
        }
    } else {
        return error.PidfdGetfdFailed;
    }

    const mem_bridge = MemoryBridge.init(child_pid);

    // Now we have the notify fd! Start handling notifications
    try handle_notifications(notify_fd, mem_bridge);
}

fn handle_notifications(notify_fd: FD, mem_bridge: MemoryBridge) !void {
    std.debug.print("Starting notification handler on fd {}\n", .{notify_fd});

    const logger = Logger.init("supervisor");

    // Allocate zeroed structures
    var req: linux.SECCOMP.notif = std.mem.zeroes(linux.SECCOMP.notif);
    var resp: linux.SECCOMP.notif_resp = std.mem.zeroes(linux.SECCOMP.notif_resp);

    while (true) : ({
        // On continue, re-zero buffers
        req = std.mem.zeroes(linux.SECCOMP.notif);
        resp = std.mem.zeroes(linux.SECCOMP.notif_resp);
    }) {
        // Receive notification
        const recv_result = linux.ioctl(notify_fd, linux.SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&req));
        switch (Result(usize).from(recv_result)) {
            .Ok => {},
            .Error => |err| switch (err) {
                .NOENT => {
                    // Thrown when child exits
                    std.debug.print("Child exited, stopping notification handler\n", .{});
                    break;
                },
                else => |_| return posix.unexpectedErrno(err),
            },
        }

        const sys_call = try SysCall.parse(mem_bridge, req);
        switch (sys_call) {
            .passthrough => |sys_code| {
                logger.log("Syscall: passthrough: {s}", .{@tagName(sys_code)});
            },
            .clock_nanosleep => |inner| {
                logger.log("Syscall: clock_nanosleep", .{});
                logger.log("Original nanos: {d}", .{inner.request.nsec});

                // experiment: fuck around with sleep by overwriting requested duration in child
                var new_req = inner.request;
                new_req.nsec = @divFloor(new_req.nsec, 5); // 5x faster
                logger.log("TURBOMODE nanos: {d}", .{new_req.nsec});
                try mem_bridge.write(linux.timespec, new_req, req.data.arg2);
            },
        }

        // Allow the syscall to proceed (passthrough mode)
        resp.id = req.id;
        resp.@"error" = 0;
        resp.val = 0;
        resp.flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE;

        _ = try Result(usize).from(
            linux.ioctl(notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&resp)),
        ).unwrap();
    }
}

const SysCall = union(enum) {
    // Unsupported syscalls passthrough
    passthrough: linux.SYS,

    // Supported:
    clock_nanosleep: struct {
        clock_id: linux.clockid_t,
        flags: u64,
        request: linux.timespec,
        remain: linux.timespec,
    },

    const Self = @This();

    fn parse(mem_bridge: MemoryBridge, req: linux.SECCOMP.notif) !Self {
        const sys_code: linux.SYS = @enumFromInt(req.data.nr);
        switch (sys_code) {
            else => {
                return Self{ .passthrough = sys_code };
            },
            .clock_nanosleep => {
                return Self{
                    .clock_nanosleep = .{
                        .clock_id = @enumFromInt(req.data.arg0),
                        .flags = req.data.arg1,
                        .request = try mem_bridge.read(linux.timespec, req.data.arg2),
                        .remain = try mem_bridge.read(linux.timespec, req.data.arg3),
                    },
                };
            },
        }
    }
};

/// MemoryBridge allows cross-process reading and writing of arbitrary data from a child process
/// This is needed for cases where syscalls from a child contain pointers
/// pointing to its own process-local address space
const MemoryBridge = struct {
    child_pid: linux.pid_t,

    fn init(child_pid: linux.pid_t) @This() {
        return .{ .child_pid = child_pid };
    }

    /// Read an object of type T from child_addr in child's address space
    /// This creates a copy in the local process
    /// Remember any nested pointers returned are still in child's address space
    fn read(self: @This(), T: type, child_addr: u64) !T {
        const child_iovec: [1]posix.iovec_const = .{.{
            .base = @ptrFromInt(child_addr),
            .len = @sizeOf(T),
        }};

        var local_T: T = undefined;
        const local_iovec: [1]posix.iovec = .{.{
            .base = @ptrCast(&local_T),
            .len = @sizeOf(T),
        }};

        _ = try Result(usize).from(
            // https://man7.org/linux/man-pages/man2/process_vm_readv.2.html
            linux.process_vm_readv(
                self.child_pid,
                &local_iovec,
                &child_iovec,
                0,
            ),
        ).unwrap();
        return local_T;
    }

    /// Write an object of type T into child's address space at child_addr
    /// Misuse could seriously corrupt child process
    fn write(self: @This(), T: type, val: T, child_addr: u64) !void {
        const local_iovec: [1]posix.iovec_const = .{.{
            .base = @ptrCast(&val),
            .len = @sizeOf(T),
        }};

        const child_iovec: [1]posix.iovec_const = .{.{
            .base = @ptrFromInt(child_addr),
            .len = @sizeOf(T),
        }};

        _ = try Result(usize).from(
            // https://man7.org/linux/man-pages/man2/process_vm_writev.2.html
            linux.process_vm_writev(
                self.child_pid,
                &local_iovec,
                &child_iovec,
                0,
            ),
        ).unwrap();
    }
};

const Logger = struct {
    name: []const u8,

    fn init(name: []const u8) @This() {
        return .{ .name = name };
    }

    fn log(self: @This(), comptime format: []const u8, args: anytype) void {
        var buf: [1024]u8 = undefined;
        const fmtlog = std.fmt.bufPrint(&buf, format, args) catch unreachable;
        std.debug.print("\x1b[95m[{s}]\t{s}\x1b[0m\n", .{ self.name, fmtlog });
    }
};
