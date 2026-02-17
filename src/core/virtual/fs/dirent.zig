const std = @import("std");

// d_ino (u64) + d_off (i64) + d_reclen (u16) + d_type (u8)
pub const NAME_OFFSET = 19;

/// Compute the aligned record length for a dirent with the given name length.
pub fn recLen(name_len: usize) usize {
    return std.mem.alignForward(usize, NAME_OFFSET + name_len + 1, 8);
}

/// Write a linux_dirent64 entry into `buf` using field-by-field serialization.
/// `d_off` is the opaque cookie for lseek(fd, d_off, SEEK_SET) to resume at the next entry.
pub fn writeDirent(buf: []u8, ino: u64, d_off: i64, rec_len: u16, d_type: u8, name: []const u8) void {
    std.mem.writeInt(u64, buf[0..8], ino, .little);
    std.mem.writeInt(i64, buf[8..16], d_off, .little);
    std.mem.writeInt(u16, buf[16..18], rec_len, .little);
    buf[18] = d_type;
    @memcpy(buf[NAME_OFFSET..][0..name.len], name);
    @memset(buf[NAME_OFFSET + name.len .. rec_len], 0);
}
