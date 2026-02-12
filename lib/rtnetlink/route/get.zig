const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const NetLink = @import("../rtnetlink.zig");
const RouteMessage = @import("route.zig");
const Attr = @import("attrs.zig").RtAttr;
const nalign = @import("../utils.zig").nalign;

const Get = @This();

msg: RouteMessage,
nl: *NetLink,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, nl: *NetLink) Get {
    var msg = RouteMessage.init(allocator, .get);
    msg.msg.hdr.scope = .Universe;
    msg.msg.hdr.type = .Unspec;
    msg.msg.hdr.table = .Unspec;
    msg.msg.hdr.protocol = .Unspec;

    msg.hdr.flags |= linux.NLM_F_DUMP;

    return .{
        .nl = nl,
        .msg = msg,
        .allocator = allocator,
    };
}

pub fn exec(self: *Get) ![]RouteMessage {
    const msg = try self.msg.compose();
    defer self.allocator.free(msg);

    try self.nl.send(msg);
    return try self.recv();
}

fn recv(self: *Get) ![]RouteMessage {
    var buff: [4096]u8 = undefined;

    var n = try self.nl.recv(&buff);

    var response = std.ArrayList(RouteMessage).empty;
    errdefer response.deinit(self.allocator);
    outer: while (n != 0) {
        var d: usize = 0;
        while (d < n) {
            const msg = (try self.parseMessage(buff[d..n])) orelse break :outer;
            try response.append(self.allocator, msg);
            if (msg.hdr.len == 0) return error.InvalidResponse;
            const frame_len = nalign(msg.hdr.len);
            if (d + frame_len > n) return error.InvalidResponse;
            d += frame_len;
        }
        n = try self.nl.recv(&buff);
    }
    return response.toOwnedSlice(self.allocator);
}

fn parseMessage(self: *Get, buff: []u8) !?RouteMessage {
    if (buff.len < @sizeOf(linux.nlmsghdr)) return error.InvalidResponse;

    const header = std.mem.bytesAsValue(linux.nlmsghdr, buff[0..@sizeOf(linux.nlmsghdr)]);
    if (header.type == .ERROR) {
        if (buff.len < @sizeOf(NetLink.NlMsgError)) return error.InvalidResponse;
        const response = std.mem.bytesAsValue(NetLink.NlMsgError, buff[0..]);
        try NetLink.handle_ack(response.*);
        return error.InvalidResponse;
    } else if (header.type == .DONE) {
        return null;
    }

    if (header.len < @sizeOf(linux.nlmsghdr) + @sizeOf(RouteMessage.RouteHeader) or header.len > buff.len) {
        return error.InvalidResponse;
    }

    var msg = RouteMessage.init(self.allocator, .create);
    errdefer msg.deinit();

    const len = header.len;
    msg.hdr = header.*;

    const hdr = std.mem.bytesAsValue(RouteMessage.RouteHeader, buff[@sizeOf(linux.nlmsghdr)..]);
    msg.msg.hdr = hdr.*;

    var start: usize = @sizeOf(RouteMessage.RouteHeader) + @sizeOf(linux.nlmsghdr);
    while (start + @sizeOf(Attr) <= len) {
        const attr = std.mem.bytesAsValue(Attr, buff[start .. start + @sizeOf(Attr)]);
        if (attr.len < @sizeOf(Attr)) return error.InvalidResponse;
        if (start + attr.len > len) return error.InvalidResponse;
        const payload_len = attr.len - @sizeOf(Attr);
        // TODO: parse more attrs
        switch (attr.type) {
            .Gateway => {
                if (msg.msg.hdr.family != linux.AF.INET) return error.UnsupportedAddressFamily;
                if (payload_len != 4) return error.InvalidResponse;
                try msg.addAttr(.{ .gateway = buff[start + @sizeOf(Attr) .. start + @sizeOf(Attr) + 4][0..4].* });
            },
            .Oif => {
                if (payload_len != @sizeOf(u32)) return error.InvalidResponse;
                const value = std.mem.bytesAsValue(u32, buff[start + @sizeOf(Attr) .. start + @sizeOf(Attr) + @sizeOf(u32)]);
                try msg.addAttr(.{ .output_if = value.* });
            },
            else => {},
        }

        start += nalign(attr.len);
    }

    return msg;
}

test "parseMessage returns null for DONE frame" {
    var get = Get{ .msg = undefined, .nl = undefined, .allocator = std.testing.allocator };
    var buff: [@sizeOf(linux.nlmsghdr)]u8 = [_]u8{0} ** @sizeOf(linux.nlmsghdr);
    const hdr = linux.nlmsghdr{
        .len = @intCast(@sizeOf(linux.nlmsghdr)),
        .type = .DONE,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));
    try std.testing.expect((try get.parseMessage(&buff)) == null);
}

test "parseMessage rejects zero-length header" {
    var get = Get{ .msg = undefined, .nl = undefined, .allocator = std.testing.allocator };
    var buff: [@sizeOf(linux.nlmsghdr)]u8 = [_]u8{0} ** @sizeOf(linux.nlmsghdr);
    const hdr = linux.nlmsghdr{
        .len = 0,
        .type = .RTM_NEWROUTE,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));
    try std.testing.expectError(error.InvalidResponse, get.parseMessage(&buff));
}

test "parseMessage rejects malformed route attribute length" {
    var get = Get{ .msg = undefined, .nl = undefined, .allocator = std.testing.allocator };
    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(RouteMessage.RouteHeader) + @sizeOf(Attr);
    var buff: [total_len]u8 = [_]u8{0} ** total_len;

    const hdr = linux.nlmsghdr{
        .len = @intCast(total_len),
        .type = .RTM_NEWROUTE,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));

    const route_hdr = RouteMessage.RouteHeader{};
    const route_off = @sizeOf(linux.nlmsghdr);
    @memcpy(buff[route_off .. route_off + @sizeOf(RouteMessage.RouteHeader)], std.mem.asBytes(&route_hdr));

    const bad_attr = Attr{ .len = @intCast(@sizeOf(Attr) - 1), .type = .Gateway };
    const attr_off = route_off + @sizeOf(RouteMessage.RouteHeader);
    @memcpy(buff[attr_off .. attr_off + @sizeOf(Attr)], std.mem.asBytes(&bad_attr));

    try std.testing.expectError(error.InvalidResponse, get.parseMessage(&buff));
}

test "parseMessage rejects route attribute overrunning frame" {
    var get = Get{ .msg = undefined, .nl = undefined, .allocator = std.testing.allocator };
    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(RouteMessage.RouteHeader) + @sizeOf(Attr);
    var buff: [total_len]u8 = [_]u8{0} ** total_len;

    const hdr = linux.nlmsghdr{
        .len = @intCast(total_len),
        .type = .RTM_NEWROUTE,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));

    const route_hdr = RouteMessage.RouteHeader{};
    const route_off = @sizeOf(linux.nlmsghdr);
    @memcpy(buff[route_off .. route_off + @sizeOf(RouteMessage.RouteHeader)], std.mem.asBytes(&route_hdr));

    const bad_attr = Attr{ .len = @intCast(@sizeOf(Attr) + 8), .type = .Gateway };
    const attr_off = route_off + @sizeOf(RouteMessage.RouteHeader);
    @memcpy(buff[attr_off .. attr_off + @sizeOf(Attr)], std.mem.asBytes(&bad_attr));

    try std.testing.expectError(error.InvalidResponse, get.parseMessage(&buff));
}

test "parseMessage repeated parse/deinit does not leak" {
    var get = Get{ .msg = undefined, .nl = undefined, .allocator = std.testing.allocator };
    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(RouteMessage.RouteHeader);
    var buff: [total_len]u8 = [_]u8{0} ** total_len;

    const hdr = linux.nlmsghdr{
        .len = @intCast(total_len),
        .type = .RTM_NEWROUTE,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));

    const route_hdr = RouteMessage.RouteHeader{};
    const route_off = @sizeOf(linux.nlmsghdr);
    @memcpy(buff[route_off .. route_off + @sizeOf(RouteMessage.RouteHeader)], std.mem.asBytes(&route_hdr));

    var i: usize = 0;
    while (i < 128) : (i += 1) {
        var parsed = (try get.parseMessage(&buff)).?;
        parsed.deinit();
    }
}

test "parseMessage rejects IPv6 gateway payload for unsupported family" {
    var get = Get{ .msg = undefined, .nl = undefined, .allocator = std.testing.allocator };
    const payload_len = 16;
    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(RouteMessage.RouteHeader) + @sizeOf(Attr) + payload_len;
    var buff: [total_len]u8 = [_]u8{0} ** total_len;

    const hdr = linux.nlmsghdr{
        .len = @intCast(total_len),
        .type = .RTM_NEWROUTE,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));

    const route_hdr = RouteMessage.RouteHeader{ .family = linux.AF.INET6 };
    const route_off = @sizeOf(linux.nlmsghdr);
    @memcpy(buff[route_off .. route_off + @sizeOf(RouteMessage.RouteHeader)], std.mem.asBytes(&route_hdr));

    const gateway_attr = Attr{ .len = @intCast(@sizeOf(Attr) + payload_len), .type = .Gateway };
    const attr_off = route_off + @sizeOf(RouteMessage.RouteHeader);
    @memcpy(buff[attr_off .. attr_off + @sizeOf(Attr)], std.mem.asBytes(&gateway_attr));

    try std.testing.expectError(error.UnsupportedAddressFamily, get.parseMessage(&buff));
}
