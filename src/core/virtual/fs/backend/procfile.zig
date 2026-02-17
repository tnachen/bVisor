const std = @import("std");
const linux = std.os.linux;
const Thread = @import("../../proc/Thread.zig");
const NsTgid = Thread.NsTgid;
const Namespace = @import("../../proc/Namespace.zig");
const dirent = @import("../dirent.zig");

/// Procfile handles all internals of /proc/<nstgid_or_self>/...
/// The trick is that the content is generated at opentime
/// To avoid tracking different variants of ProcFile
pub const ProcFile = struct {
    content: [256]u8,
    content_len: usize,
    offset: usize,
    is_dir: bool = false,

    pub const ProcTarget = union(enum) {
        dir_proc,
        dir_pid_self,
        dir_pid: NsTgid,
        self_status,
        nstgid_status: NsTgid,
    };

    pub fn parseProcPath(path: []const u8) !ProcTarget {
        if (std.mem.eql(u8, path, "/proc")) return .dir_proc;

        const prefix = "/proc/";
        if (!std.mem.startsWith(u8, path, prefix)) return error.NOENT;
        const remainder = path[prefix.len..];
        if (remainder.len == 0) return .dir_proc;

        // /proc/self (directory) or /proc/self/status (file)
        if (std.mem.startsWith(u8, remainder, "self")) {
            const after_self = remainder["self".len..];
            if (after_self.len == 0) return .dir_pid_self;
            if (std.mem.eql(u8, after_self, "/status")) return .self_status;
            return error.NOENT;
        }

        // /proc/<N> (directory) or /proc/<N>/status (file)
        const slash_pos = std.mem.indexOfScalar(u8, remainder, '/');
        const nstgid_str = if (slash_pos) |pos| remainder[0..pos] else remainder;

        const nstgid = std.fmt.parseInt(NsTgid, nstgid_str, 10) catch return error.NOENT;
        if (nstgid <= 0) return error.NOENT;

        if (slash_pos) |pos| {
            const subpath = remainder[pos..];
            if (std.mem.eql(u8, subpath, "/status")) return .{ .nstgid_status = nstgid };
            return error.NOENT;
        }

        return .{ .dir_pid = nstgid };
    }

    pub fn open(caller: *Thread, path: []const u8) !ProcFile {
        const target = try parseProcPath(path);

        var self = ProcFile{
            .content = undefined,
            .content_len = 0,
            .offset = 0,
        };

        switch (target) {
            .dir_proc, .dir_pid_self => {
                self.is_dir = true;
            },
            .dir_pid => |nstgid| {
                _ = caller.namespace.threads.get(nstgid) orelse return error.NOENT;
                self.is_dir = true;
            },
            .self_status => {
                self.content_len = try formatStatus(&self.content, caller);
            },
            .nstgid_status => |nstgid| {
                const target_thread = caller.namespace.threads.get(nstgid) orelse return error.NOENT;
                self.content_len = try formatStatus(&self.content, target_thread);
            },
        }

        return self;
    }

    fn formatStatus(buf: *[256]u8, target: *Thread) !usize {
        const leader = try target.thread_group.getLeader();
        const nstgid = target.namespace.getNsTid(leader) orelse 0;

        const nsptgid: NsTgid = if (target.thread_group.parent) |parent_process| blk: {
            const parent = try parent_process.getLeader();
            break :blk target.namespace.getNsTid(parent) orelse 0;
        } else 0;

        // TODO: support more status content lookup, this isn't 100% compatible
        // We also use the same name for everything
        const name = "bvisor-guest";
        const slice = std.fmt.bufPrint(buf, "Name:\t{s}\nPid:\t{d}\nPPid:\t{d}\n", .{ name, nstgid, nsptgid }) catch unreachable;
        return slice.len;
    }

    /// Synthesize linux_dirent64 entries for a /proc directory listing.
    /// `caller` is needed to enumerate visible PIDs from the caller's namespace.
    /// `opened_path` distinguishes /proc (list PIDs) from /proc/<pid> (list subfiles).
    pub fn getdents64(_: *ProcFile, buf: []u8, caller: *Thread, opened_path: []const u8, dirents_offset: *usize) !usize {
        var names_buf: [64][]const u8 = undefined;
        var num_fmt_buf: [64][16]u8 = undefined;
        var name_count: usize = 0;

        names_buf[name_count] = ".";
        name_count += 1;
        names_buf[name_count] = "..";
        name_count += 1;

        if (std.mem.eql(u8, opened_path, "/proc")) {
            names_buf[name_count] = "self";
            name_count += 1;

            var iter = caller.namespace.threads.iterator();
            while (iter.next()) |entry| {
                if (name_count >= names_buf.len) break;
                const nstgid = entry.key_ptr.*;
                if (nstgid <= 0) continue;
                const slice = std.fmt.bufPrint(&num_fmt_buf[name_count - 3], "{d}", .{nstgid}) catch continue;
                names_buf[name_count] = slice;
                name_count += 1;
            }
        } else {
            // /proc/<pid> or /proc/self — list known subfiles
            // TODO: expand as more /proc/<pid>/* files are virtualized
            names_buf[name_count] = "status";
            name_count += 1;
        }

        var buf_pos: usize = 0;
        var entry_idx: usize = 0;

        for (names_buf[0..name_count]) |name| {
            if (entry_idx < dirents_offset.*) {
                entry_idx += 1;
                continue;
            }

            const rec_len = dirent.recLen(name.len);
            if (buf_pos + rec_len > buf.len) break;

            const d_type: u8 = if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, ".."))
                linux.DT.DIR
            else if (std.mem.eql(u8, name, "self"))
                linux.DT.LNK
            else if (std.mem.eql(u8, name, "status"))
                linux.DT.REG
            else
                linux.DT.DIR; // numeric PID entries are directories

            dirent.writeDirent(buf[buf_pos..], entry_idx + 1, @intCast(entry_idx + 1), @intCast(rec_len), d_type, name);
            buf_pos += rec_len;
            entry_idx += 1;
            dirents_offset.* += 1;
        }

        return buf_pos;
    }

    pub fn read(self: *ProcFile, buf: []u8) !usize {
        const remaining = self.content[self.offset..self.content_len];
        if (remaining.len == 0) return 0;
        const n = @min(buf.len, remaining.len);
        @memcpy(buf[0..n], remaining[0..n]);
        self.offset += n;
        return n;
    }

    pub fn write(self: *ProcFile, data: []const u8) !usize {
        _ = self;
        _ = data;
        return error.ROFS;
    }

    pub fn close(self: *ProcFile) void {
        _ = self;
    }

    pub fn statx(self: *ProcFile) !linux.Statx {
        var statx_buf: linux.Statx = std.mem.zeroes(linux.Statx);

        // No kernel fd, so build ourselves
        statx_buf.mask = .{
            .MODE = true,
            .NLINK = true,
            .SIZE = true,
        };

        if (self.is_dir) {
            statx_buf.mode = linux.S.IFDIR | 0o555;
            statx_buf.nlink = 2;
            statx_buf.size = 0;
        } else {
            statx_buf.mode = linux.S.IFREG | 0o444;
            statx_buf.nlink = 1;
            statx_buf.size = self.content_len;
        }

        statx_buf.blksize = 4096; // doesn't require a mask bit because none exists

        // TODO: implement these
        // statx_buf.ino // as counter in FdTable?
        // statx_buf.uid // in File?
        // statx_buf.gid // in File?
        // statx_buf.atime // in backend struct? Procfile can store open_time : i64, ...
        // statx_buf.mtime // in backend struct?
        // statx_buf.ctime // in backend struct?
        // statx_buf.dev // fake device number, global to sandbox?

        return statx_buf;
    }

    pub fn statxByPath(caller: *Thread, path: []const u8) !linux.Statx {
        var file = try ProcFile.open(caller, path);
        return file.statx();
    }

    pub fn lseek(self: *ProcFile, offset: i64, whence: u32) !i64 {
        const base: i64 = switch (whence) {
            linux.SEEK.SET => 0,
            linux.SEEK.CUR => @intCast(self.offset),
            linux.SEEK.END => @intCast(self.content_len),
            else => return error.INVAL,
        };
        const new_offset = std.math.add(i64, base, offset) catch return error.INVAL;
        if (new_offset < 0) return error.INVAL;
        self.offset = @intCast(new_offset);
        return new_offset;
    }

    pub fn ioctl(self: *ProcFile, request: linux.IOCTL.Request, arg: usize) !usize {
        _ = .{ self, request, arg };
        return error.NOTTY;
    }

    pub fn connect(self: *ProcFile, addr: [*]const u8, addrlen: linux.socklen_t) !void {
        _ = .{ self, addr, addrlen };
        return error.NOTSOCK;
    }

    pub fn shutdown(self: *ProcFile, how: i32) !void {
        _ = .{ self, how };
        return error.NOTSOCK;
    }

    pub fn recvFrom(self: *ProcFile, buf: []u8, flags: u32, src_addr: ?[*]u8, src_addrlen: ?*linux.socklen_t) !usize {
        _ = .{ self, buf, flags, src_addr, src_addrlen };
        return error.NOTSOCK;
    }

    pub fn sendTo(self: *ProcFile, data: []const u8, flags: u32, dest_addr: ?[*]const u8, addrlen: linux.socklen_t) !usize {
        _ = .{ self, data, flags, dest_addr, addrlen };
        return error.NOTSOCK;
    }
};

const testing = std.testing;
const Threads = @import("../../proc/Threads.zig");
const proc_info = @import("../../../utils/proc_info.zig");

test "parseProcPath - /proc/self" {
    const target = try ProcFile.parseProcPath("/proc/self");
    try testing.expect(target == .dir_pid_self);
}

test "parseProcPath - /proc/self/status" {
    const target = try ProcFile.parseProcPath("/proc/self/status");
    try testing.expect(target == .self_status);
}

test "parseProcPath - /proc/123" {
    const target = try ProcFile.parseProcPath("/proc/123");
    try testing.expectEqual(ProcFile.ProcTarget{ .dir_pid = 123 }, target);
}

test "parseProcPath - /proc/123/status" {
    const target = try ProcFile.parseProcPath("/proc/123/status");
    try testing.expectEqual(ProcFile.ProcTarget{ .nstgid_status = 123 }, target);
}

test "parseProcPath - /proc/ resolves to dir_proc" {
    const target = try ProcFile.parseProcPath("/proc/");
    try testing.expect(target == .dir_proc);
}

test "parseProcPath - /proc/self/bogus is invalid" {
    try testing.expectError(error.NOENT, ProcFile.parseProcPath("/proc/self/bogus"));
}

test "parseProcPath - /proc/abc is invalid" {
    try testing.expectError(error.NOENT, ProcFile.parseProcPath("/proc/abc"));
}

test "parseProcPath - /proc/123/bogus is invalid" {
    try testing.expectError(error.NOENT, ProcFile.parseProcPath("/proc/123/bogus"));
}

test "parseProcPath - /wrong/prefix is invalid" {
    try testing.expectError(error.NOENT, ProcFile.parseProcPath("/wrong/self"));
}

test "open /proc/self opens as directory" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self");
    try testing.expect(file.is_dir);
    var buf: [64]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}

test "open /proc/self/status contains Pid and PPid" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    // Add a child
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(0));
    const child = v_threads.lookup.get(200).?;

    var file = try ProcFile.open(child, "/proc/self/status");
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];

    // Child's NsTgid is 200, parent is 100
    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t200\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "PPid:\t100\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "Name:\tbvisor-guest\n") != null);
}

test "open /proc/<N> opens as directory for visible Thread" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(0));

    var file = try ProcFile.open(root, "/proc/200");
    try testing.expect(file.is_dir);
    var buf: [64]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}

test "open /proc/<N> returns error for non-existent pid" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    try testing.expectError(error.NOENT, ProcFile.open(root, "/proc/999"));
}

test "open /proc/<N>/status for visible Thread" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();
    defer proc_info.mock.reset(allocator);

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    // Create child in new namespace
    const nstids = [_]NsTgid{ 200, 1 };
    try proc_info.mock.setupNsTids(allocator, 200, &nstids);
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(std.os.linux.CLONE.NEWPID));
    const child = v_threads.lookup.get(200).?;

    // From child's namespace, child is PID 1. PPid is 0 (parent not visible in child ns)
    var file = try ProcFile.open(child, "/proc/1/status");
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];

    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t1\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "PPid:\t0\n") != null);
}

test "write returns ReadOnlyFileSystem" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self/status");
    try testing.expectError(error.ROFS, file.write("test"));
}

test "parseProcPath - /proc/0 (zero PID) is invalid" {
    try testing.expectError(error.NOENT, ProcFile.parseProcPath("/proc/0"));
}

test "parseProcPath - /proc/-1 (negative) is invalid" {
    try testing.expectError(error.NOENT, ProcFile.parseProcPath("/proc/-1"));
}

test "child in new namespace (CLONE_NEWPID) /proc/self opens as directory" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();
    defer proc_info.mock.reset(allocator);

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    const nstids = [_]NsTgid{ 200, 1 };
    try proc_info.mock.setupNsTids(allocator, 200, &nstids);
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(std.os.linux.CLONE.NEWPID));
    const child = v_threads.lookup.get(200).?;

    var file = try ProcFile.open(child, "/proc/self");
    try testing.expect(file.is_dir);
}

test "open /proc/self/status - child with parent invisible (new namespace) has PPid 0" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();
    defer proc_info.mock.reset(allocator);

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    const nstids = [_]NsTgid{ 200, 1 };
    try proc_info.mock.setupNsTids(allocator, 200, &nstids);
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(std.os.linux.CLONE.NEWPID));
    const child = v_threads.lookup.get(200).?;

    var file = try ProcFile.open(child, "/proc/self/status");
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];

    try testing.expect(std.mem.indexOf(u8, content, "PPid:\t0\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t1\n") != null);
}

test "open /proc/self/status - child with visible parent has correct PPid" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(0));
    const child = v_threads.lookup.get(200).?;

    var file = try ProcFile.open(child, "/proc/self/status");
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];

    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t200\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "PPid:\t100\n") != null);
}

test "open /proc/N where N is in different namespace returns FileNotFound" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();
    defer proc_info.mock.reset(allocator);

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    // Child in new namespace
    const nstids = [_]NsTgid{ 200, 1 };
    try proc_info.mock.setupNsTids(allocator, 200, &nstids);
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(std.os.linux.CLONE.NEWPID));
    const child = v_threads.lookup.get(200).?;

    // Child cannot see root (NsTgid 100) since root is not in child's namespace
    try testing.expectError(error.NOENT, ProcFile.open(child, "/proc/100"));
}

test "read past end returns 0 (EOF)" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self/status");

    // Read all content
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expect(n > 0);

    // Second read should return 0 (EOF)
    const n2 = try file.read(&buf);
    try testing.expectEqual(@as(usize, 0), n2);
}

test "read with 1-byte buffer walks through content" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(5);
    const proc = v_threads.lookup.get(5).?;

    // Use /proc/self/status which has file content
    var file = try ProcFile.open(proc, "/proc/self/status");
    // Content starts with "Name:\tbvisor-guest\n"

    var byte_buf: [1]u8 = undefined;
    const n = try file.read(&byte_buf);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 'N'), byte_buf[0]);
}

test "close is no-op" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self/status");
    file.close();
}

test "content frozen at open time (snapshot semantics)" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    // Open /proc/self/status — content captured at open time
    var file = try ProcFile.open(root, "/proc/self/status");

    // Now add a child - this shouldn't affect the already-opened file
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(0));

    // Read from the already-opened file - should still show original content
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];
    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t100\n") != null);
}

test "offset tracking works across multiple reads" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

    // Use /proc/self/status which produces "Name:\tbvisor-guest\nPid:\t100\nPPid:\t0\n"
    var file = try ProcFile.open(proc, "/proc/self/status");

    // Read 5 bytes at a time
    var buf: [5]u8 = undefined;
    var n = try file.read(&buf);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualStrings("Name:", buf[0..n]);

    n = try file.read(&buf);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualStrings("\tbvis", buf[0..n]);
}
