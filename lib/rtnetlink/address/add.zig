const Addr = @import("address.zig");
const RtNetLink = @import("../rtnetlink.zig");
const std = @import("std");
const linux = std.os.linux;

const AddrAdd = @This();

pub const Options = struct {
    index: c_int,
    addr: [4]u8,
    prefix_len: u8,
};

msg: Addr,
nl: *RtNetLink,
opts: Options,

pub fn init(allocator: std.mem.Allocator, nl: *RtNetLink, options: Options) AddrAdd {
    const msg = Addr.init(allocator, .create);
    return .{ .msg = msg, .nl = nl, .opts = options };
}

fn applyOptions(self: *AddrAdd) !void {
    if (self.opts.prefix_len > 32) return error.InvalidPrefixLength;

    self.msg.msg.hdr.index = @intCast(self.opts.index);
    self.msg.msg.hdr.prefix_len = self.opts.prefix_len;
    try self.msg.addAttr(.{ .address = self.opts.addr });
    try self.msg.addAttr(.{ .local = self.opts.addr });

    try self.msg.addAttr(.{ .broadcast = computeBroadcast(self.opts.addr, self.opts.prefix_len) });
}

fn computeBroadcast(addr: [4]u8, prefix_len: u8) [4]u8 {
    if (prefix_len >= 32) return addr;

    const addr_be = std.mem.readInt(u32, &addr, .big);
    const netmask: u32 = if (prefix_len == 0)
        0
    else blk: {
        const host_bits: u5 = @intCast(32 - prefix_len);
        break :blk @as(u32, 0xffff_ffff) << host_bits;
    };
    const broadcast = addr_be | ~netmask;

    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, broadcast, .big);
    return out;
}

pub fn exec(self: *AddrAdd) !void {
    try self.applyOptions();

    const data = try self.msg.compose();
    defer self.msg.allocator.free(data);

    try self.nl.send(data);
    return self.nl.recv_ack();
}

test "computeBroadcast keeps /32 unchanged" {
    try std.testing.expectEqual([4]u8{ 10, 1, 2, 3 }, computeBroadcast(.{ 10, 1, 2, 3 }, 32));
}

test "computeBroadcast computes /24 broadcast" {
    try std.testing.expectEqual([4]u8{ 192, 168, 12, 255 }, computeBroadcast(.{ 192, 168, 12, 34 }, 24));
}

test "computeBroadcast computes /0 broadcast" {
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 255 }, computeBroadcast(.{ 10, 20, 30, 40 }, 0));
}
