const builtin = @import("builtin");
const impl = if (builtin.is_test)
    @import("impl/testing.zig")
else
    @import("impl/linux.zig");

pub const seize_for_clone = impl.seize_for_clone;
pub const wait_clone_event = impl.wait_clone_event;
pub const set_return_value = impl.set_return_value;
pub const detach = impl.detach;
pub const detach_child = impl.detach_child;

// Re-export testing utilities when in test mode
pub const testing = if (builtin.is_test) impl else struct {};
