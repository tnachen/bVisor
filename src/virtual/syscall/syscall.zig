const std = @import("std");
const linux = std.os.linux;
const types = @import("../../types.zig");
const Logger = types.Logger;
const Supervisor = @import("../../Supervisor.zig");

// All supported syscalls
const Writev = @import("handlers/Writev.zig");
const OpenAt = @import("handlers/OpenAt.zig");
const Clone = @import("handlers/Clone.zig");
const GetPid = @import("handlers/GetPid.zig");
const GetPPid = @import("handlers/GetPPid.zig");
const Kill = @import("handlers/Kill.zig");
const ExitGroup = @import("handlers/ExitGroup.zig");

/// Union of all virtualized syscalls.
pub const Syscall = union(enum) {
    _blocked: Blocked, // TODO: implement at bpf layer
    _not_implemented: NotImplemented,
    writev: Writev,
    openat: OpenAt,
    clone: Clone,
    getpid: GetPid,
    getppid: GetPPid,
    kill: Kill,
    exit_group: ExitGroup,

    const Self = @This();

    /// Parse seccomp notif into Syscall
    /// Null return means the syscall should passthrough // todo: implement at bpf layer
    pub fn parse(notif: linux.SECCOMP.notif) !?Self {
        const sys_code: linux.SYS = @enumFromInt(notif.data.nr);
        switch (sys_code) {
            .writev => return .{ .writev = try Writev.parse(notif) },
            .openat => return .{ .openat = try OpenAt.parse(notif) },
            .clone => return .{ .clone = try Clone.parse(notif) },
            .getpid => return .{ .getpid = GetPid.parse(notif) },
            .getppid => return .{ .getppid = GetPPid.parse(notif) },
            .kill => return .{ .kill = Kill.parse(notif) },
            .exit_group => return .{ .exit_group = ExitGroup.parse(notif) },
            else => {
                // Check if the syscall is explicitly blocked
                for (blocked) |blocked_sys| {
                    if (blocked_sys == sys_code) {
                        return .{ ._blocked = Blocked.parse(notif) };
                    }
                }

                // Check if the syscall is not implemented
                for (not_implemented) |not_impl_sys| {
                    if (not_impl_sys == sys_code) {
                        return .{ ._not_implemented = NotImplemented.parse(notif) };
                    }
                }

                // Else not supported, passthrough
                return null;
            },
        }
    }

    pub fn handle(self: Self, supervisor: *Supervisor) !Self.Result {
        return switch (self) {
            // Inline else forces all enum variants to have .handle(supervisor) signatures
            inline else => |inner| inner.handle(supervisor),
        };
    }

    pub fn handle_exit(self: Self, supervisor: *Supervisor) !void {
        // only needed for clone
        if (self == .clone) {
            return self.clone.handle_exit(supervisor);
        }
        return;
    }

    pub const Result = union(enum) {
        use_kernel: void,
        reply: Reply,

        pub const Reply = struct {
            val: i64,
            errno: i32,
        };

        pub fn reply_success(val: i64) @This() {
            return .{ .reply = .{ .val = val, .errno = 0 } };
        }

        pub fn reply_err(errno: linux.E) @This() {
            return .{ .reply = .{ .val = 0, .errno = @intFromEnum(errno) } };
        }

        pub fn is_error(self: @This()) bool {
            return switch (self) {
                .use_kernel => false,
                .reply => |reply| reply.errno != 0,
            };
        }
    };
};

/// Handler to block any explicitly blocked syscalls
const blocked = [_]linux.SYS{
    .ptrace,
};

const Blocked = struct {
    const Self = @This();

    pub fn parse(_: linux.SECCOMP.notif) Self {
        return .{};
    }

    pub fn handle(_: Self, _: *Supervisor) !Syscall.Result {
        return Syscall.Result.reply_err(.PERM);
    }
};

/// Syscalls that are not yet implemented - return ENOSYS
const not_implemented = [_]linux.SYS{
    .gettid,
    .tkill,
    .tgkill,
    .set_tid_address,
    .wait4,
    .waitid,
    .getpgid,
    .setpgid,
    .getsid,
    .setsid,
};

const NotImplemented = struct {
    const Self = @This();

    pub fn parse(_: linux.SECCOMP.notif) Self {
        return .{};
    }

    pub fn handle(_: Self, _: *Supervisor) !Syscall.Result {
        return Syscall.Result.reply_err(.NOSYS);
    }
};
