const std = @import("std");
const types = @import("types.zig");
const Logger = types.Logger;
const setup_and_run = @import("setup.zig").setup_and_run;
const smoke_test = @import("smoke_test.zig").smoke_test;

test {
    _ = @import("Supervisor.zig");
    _ = @import("virtual/proc/Procs.zig");
    _ = @import("virtual/fs/FD.zig");
    _ = @import("virtual/fs/FdTable.zig");
    _ = @import("virtual/syscall/handlers/OpenAt.zig");
    _ = @import("virtual/syscall/handlers/Clone.zig");
}

pub fn main() !void {
    const logger = Logger.init(.prefork);

    // Run the smoke test inside the sandbox
    logger.log("Running smoke test with syscall interception:", .{});
    try setup_and_run(smoke_test);
}
