const std = @import("std");
const Tombstones = @import("../Tombstones.zig");

// d_ino (u64) + d_off (i64) + d_reclen (u16) + d_type (u8)
pub const NAME_OFFSET = 19;

pub const MAX_DIR_ENTRIES = 2048;
pub const MAX_NAME_STORAGE = 32768;

pub const DirEntry = struct {
    name: []const u8, // points into name_storage
    d_type: u8,
};

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

/// Parse dirent64 entries from raw kernel buffer and append to the entry list.
pub fn collectDirents(
    raw: []const u8,
    entries: []DirEntry,
    count: *usize,
    name_storage: *[MAX_NAME_STORAGE]u8,
    name_pos: *usize,
) void {
    var pos: usize = 0;
    while (pos + NAME_OFFSET < raw.len and count.* < entries.len) {
        const rec_len_ = std.mem.readInt(u16, raw[pos + 16 ..][0..2], .little);
        if (rec_len_ < NAME_OFFSET or pos + rec_len_ > raw.len) break;

        const d_type = raw[pos + 18];
        const name_end = pos + rec_len_;
        const name_bytes = raw[pos + NAME_OFFSET .. name_end];
        const null_pos = std.mem.indexOfScalar(u8, name_bytes, 0) orelse name_bytes.len;
        const name = name_bytes[0..null_pos];

        if (name_pos.* + name.len <= name_storage.len) {
            @memcpy(name_storage[name_pos.*..][0..name.len], name);
            entries[count.*] = .{
                .name = name_storage[name_pos.*..][0..name.len],
                .d_type = d_type,
            };
            count.* += 1;
            name_pos.* += name.len;
        }

        pos += rec_len_;
    }
}

/// Like collectDirents, but skips entries whose name already exists in the list.
pub fn collectDirentsDedup(
    raw: []const u8,
    entries: []DirEntry,
    count: *usize,
    name_storage: *[MAX_NAME_STORAGE]u8,
    name_pos: *usize,
) void {
    var pos: usize = 0;
    while (pos + NAME_OFFSET < raw.len and count.* < entries.len) {
        const rec_len_ = std.mem.readInt(u16, raw[pos + 16 ..][0..2], .little);
        if (rec_len_ < NAME_OFFSET or pos + rec_len_ > raw.len) break;

        const d_type = raw[pos + 18];
        const name_end = pos + rec_len_;
        const name_bytes = raw[pos + NAME_OFFSET .. name_end];
        const null_pos = std.mem.indexOfScalar(u8, name_bytes, 0) orelse name_bytes.len;
        const name = name_bytes[0..null_pos];

        if (!nameExists(entries[0..count.*], name)) {
            if (name_pos.* + name.len <= name_storage.len) {
                @memcpy(name_storage[name_pos.*..][0..name.len], name);
                entries[count.*] = .{
                    .name = name_storage[name_pos.*..][0..name.len],
                    .d_type = d_type,
                };
                count.* += 1;
                name_pos.* += name.len;
            }
        }

        pos += rec_len_;
    }
}

fn nameExists(entries: []const DirEntry, name: []const u8) bool {
    for (entries) |e| {
        if (std.mem.eql(u8, e.name, name)) return true;
    }
    return false;
}

/// Serialize directory entries into a buffer, filtering tombstoned and already-returned entries.
pub fn serializeEntries(
    entries: []const DirEntry,
    buf: []u8,
    dir_path: []const u8,
    dirents_offset: *usize,
    tombstones: *const Tombstones,
) usize {
    var buf_pos: usize = 0;
    var entry_idx: usize = 0;

    for (entries) |entry| {
        if (entry_idx < dirents_offset.*) {
            entry_idx += 1;
            continue;
        }

        if (!std.mem.eql(u8, entry.name, ".") and !std.mem.eql(u8, entry.name, "..") and tombstones.isChildTombstoned(dir_path, entry.name)) {
            entry_idx += 1;
            dirents_offset.* += 1;
            continue;
        }

        const rec_len_ = recLen(entry.name.len);
        if (buf_pos + rec_len_ > buf.len) break;

        writeDirent(
            buf[buf_pos..],
            entry_idx + 1,
            @intCast(entry_idx + 1),
            @intCast(rec_len_),
            entry.d_type,
            entry.name,
        );

        buf_pos += rec_len_;
        entry_idx += 1;
        dirents_offset.* += 1;
    }

    return buf_pos;
}
