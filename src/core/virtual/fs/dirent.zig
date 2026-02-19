const std = @import("std");
const Allocator = std.mem.Allocator;
const Tombstones = @import("../Tombstones.zig");

// d_ino (u64) + d_off (i64) + d_reclen (u16) + d_type (u8)
pub const NAME_OFFSET = 19;

pub const DirEntryMap = std.StringArrayHashMapUnmanaged(u8);

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
/// If dedup is true, existing entries are not overwritten
pub fn collectDirents(
    allocator: Allocator,
    raw: []const u8,
    map: *DirEntryMap,
    dedup: bool,
) !void {
    var pos: usize = 0;
    while (pos + NAME_OFFSET < raw.len) {
        const rec_len_ = std.mem.readInt(u16, raw[pos + 16 ..][0..2], .little);
        if (rec_len_ < NAME_OFFSET or pos + rec_len_ > raw.len) break;

        const d_type = raw[pos + 18];
        const name_bytes = raw[pos + NAME_OFFSET .. pos + rec_len_];
        const null_pos = std.mem.indexOfScalar(u8, name_bytes, 0) orelse name_bytes.len;
        const name = name_bytes[0..null_pos];

        const gop = try map.getOrPut(allocator, name);
        if (!gop.found_existing) {
            errdefer _ = map.orderedRemove(name);
            // Key was auto-inserted as a reference to `raw`, so dupe it
            gop.key_ptr.* = try allocator.dupe(u8, name);
            gop.value_ptr.* = d_type;
        } else if (!dedup) {
            // Overwrite d_type
            gop.value_ptr.* = d_type;
        }

        pos += rec_len_;
    }
}

/// Free all duped keys in the map.
pub fn deinitMap(allocator: Allocator, map: *DirEntryMap) void {
    for (map.keys()) |key| {
        allocator.free(key);
    }
    map.deinit(allocator);
}

/// Parse dirent names from a raw buffer (just for testing)
pub fn parseDirentNames(buf: []const u8, out: [][]const u8) usize {
    var count_: usize = 0;
    var pos: usize = 0;
    while (pos + NAME_OFFSET < buf.len and count_ < out.len) {
        const rec_len = std.mem.readInt(u16, buf[pos + 16 ..][0..2], .little);
        if (rec_len < NAME_OFFSET or pos + rec_len > buf.len) break;
        const name_bytes = buf[pos + NAME_OFFSET .. pos + rec_len];
        const null_pos = std.mem.indexOfScalar(u8, name_bytes, 0) orelse name_bytes.len;
        out[count_] = name_bytes[0..null_pos];
        count_ += 1;
        pos += rec_len;
    }
    return count_;
}

/// Check if a merged directory map is empty from the guest perspective.
/// A directory is "empty" if it contains only "." and ".." after filtering tombstones.
pub fn isMapEmpty(map: *const DirEntryMap, dir_path: []const u8, tombstones: *const Tombstones) bool {
    for (map.keys()) |name| {
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        if (!tombstones.isChildTombstoned(dir_path, name)) return false;
    }
    return true;
}

/// Serialize directory entries into a buffer, filtering tombstoned and already-returned entries.
pub fn serializeEntries(
    map: *const DirEntryMap,
    buf: []u8,
    dir_path: []const u8,
    dirents_offset: *usize,
    tombstones: *const Tombstones,
) usize {
    var buf_pos: usize = 0;
    const keys = map.keys();
    const values = map.values();
    var entry_idx: usize = 0;

    for (keys, values) |name, d_type| {
        if (entry_idx < dirents_offset.*) {
            entry_idx += 1;
            continue;
        }

        if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..") and tombstones.isChildTombstoned(dir_path, name)) {
            entry_idx += 1;
            dirents_offset.* += 1;
            continue;
        }

        const rec_len_ = recLen(name.len);
        if (buf_pos + rec_len_ > buf.len) break;

        writeDirent(
            buf[buf_pos..],
            entry_idx + 1,
            @intCast(entry_idx + 1),
            @intCast(rec_len_),
            d_type,
            name,
        );

        buf_pos += rec_len_;
        entry_idx += 1;
        dirents_offset.* += 1;
    }

    return buf_pos;
}
