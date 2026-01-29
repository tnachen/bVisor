const std = @import("std");
const posix = std.posix;

// const ProcPath = union(enum) {
//     self,
//     pid: u32, //todo: point to procsubpath? or struct
// };

// const ProcSubpath = union(enum) {
//     status,
//     // todo
// };

pub const Proc = struct {
    pub fn open(path: []const u8, flags: posix.O, mode: posix.mode_t) !Proc {
        _ = flags;
        _ = mode;
        _ = path;

        // TODO implement subpath parsing for status, self, etc.

        return error.InvalidPath;
    }

    pub fn read(self: *Proc, buf: []u8) !usize {
        _ = self;
        _ = buf;
        return error.NotImplemented;
    }

    pub fn write(self: *Proc, data: []const u8) !usize {
        _ = self;
        _ = data;
        return error.NotImplemented;
    }

    pub fn close(self: *Proc) void {
        _ = self;
        // nothing to close
    }
};

const testing = std.testing;

test "open /proc/self returns guest pid 1" {}

test "open /proc/123/status works" {}

test "read returns formatted pid string" {}

test "write returns ReadOnlyFileSystem" {}

test "offset tracking works across multiple reads" {}
