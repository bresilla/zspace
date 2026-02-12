const LinkMessage = @import("link.zig");
const RtNetLink = @import("../rtnetlink.zig");
const std = @import("std");
const log = std.log;
const nalign = @import("../utils.zig").nalign;
const linux = std.os.linux;

const LinkGet = @This();
pub const Options = struct {
    name: ?[]const u8 = null,
    index: ?u32 = null,
};

msg: LinkMessage,
nl: *RtNetLink,
opts: Options,
allocator: std.mem.Allocator,
pub fn init(allocator: std.mem.Allocator, nl: *RtNetLink, options: Options) LinkGet {
    const msg = LinkMessage.init(allocator, .get);
    return .{
        .msg = msg,
        .nl = nl,
        .opts = options,
        .allocator = allocator,
    };
}

fn name(self: *LinkGet, value: []const u8) !void {
    try self.msg.addAttr(.{ .name = value });
}

fn applyOptions(self: *LinkGet) !void {
    if (self.opts.name) |val| {
        try self.name(val);
    }
    if (self.opts.index) |val| {
        self.msg.msg.header.index = @intCast(val);
    }
}

pub fn exec(self: *LinkGet) !LinkMessage {
    try self.applyOptions();

    const data = try self.msg.compose();
    defer self.msg.allocator.free(data);

    try self.nl.send(data);
    return self.recv();
}

fn recv(self: *LinkGet) !LinkMessage {
    var buff: [4096]u8 = undefined;
    var parsed: ?LinkMessage = null;
    errdefer if (parsed) |*msg| msg.deinit();

    while (true) {
        const n = try self.nl.recv(&buff);
        if (n < @sizeOf(linux.nlmsghdr)) return error.InvalidResponse;

        var start: usize = 0;
        while (start + @sizeOf(linux.nlmsghdr) <= n) {
            const header = std.mem.bytesAsValue(linux.nlmsghdr, buff[start .. start + @sizeOf(linux.nlmsghdr)]);
            if (header.len < @sizeOf(linux.nlmsghdr)) return error.InvalidResponse;

            const frame_len = nalign(header.len);
            if (start + frame_len > n) return error.InvalidResponse;
            const frame = buff[start .. start + header.len];

            switch (header.type) {
                .DONE => {
                    if (parsed) |msg| return msg;
                    return error.InvalidResponse;
                },
                .ERROR => {
                    if (frame.len < @sizeOf(RtNetLink.NlMsgError)) return error.InvalidResponse;
                    const response = std.mem.bytesAsValue(RtNetLink.NlMsgError, frame[0..]);
                    try RtNetLink.handle_ack(response.*);
                    if (parsed) |msg| return msg;
                },
                else => {
                    var msg = try parseLinkMessage(self.allocator, frame, header.*);
                    if (parsed == null) {
                        parsed = msg;
                    } else {
                        msg.deinit();
                    }
                },
            }

            start += frame_len;
        }

        if (parsed) |msg| return msg;
    }
}

fn parseLinkMessage(allocator: std.mem.Allocator, frame: []const u8, header: linux.nlmsghdr) !LinkMessage {
    if (header.len < @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg) or header.len > frame.len) {
        return error.InvalidResponse;
    }

    var start: usize = @sizeOf(linux.nlmsghdr);
    var link_info = LinkMessage.init(allocator, .create);
    errdefer link_info.deinit();
    link_info.hdr = header;

    const ifinfo = std.mem.bytesAsValue(linux.ifinfomsg, frame[start .. start + @sizeOf(linux.ifinfomsg)]);
    start += @sizeOf(linux.ifinfomsg);
    link_info.msg.header = ifinfo.*;

    log.info("header: {}", .{header});
    log.info("ifinfo: {}", .{ifinfo});

    while (start + @sizeOf(linux.rtattr) <= header.len) {
        const rtattr = std.mem.bytesAsValue(linux.rtattr, frame[start .. start + @sizeOf(linux.rtattr)]);
        if (rtattr.len < @sizeOf(linux.rtattr)) return error.InvalidResponse;
        if (start + rtattr.len > header.len) return error.InvalidResponse;

        switch (rtattr.type.link) {
            .IFNAME => {
                if (rtattr.len == @sizeOf(linux.rtattr)) {
                    start += nalign(rtattr.len);
                    continue;
                }
                if (frame[start + rtattr.len - 1] != 0) return error.InvalidResponse;
                const value = frame[start + @sizeOf(linux.rtattr) .. start + rtattr.len - 1];
                const ifname = try allocator.alloc(u8, value.len);
                @memcpy(ifname, value);
                log.info("name: {s}", .{ifname});
                try link_info.addAttr(.{ .name_owned = ifname });
            },
            else => {},
        }

        start += nalign(rtattr.len);
    }

    return link_info;
}

test "parseLinkMessage rejects truncated header" {
    var buff: [@sizeOf(linux.nlmsghdr)]u8 = [_]u8{0} ** @sizeOf(linux.nlmsghdr);
    const hdr = linux.nlmsghdr{
        .len = @intCast(@sizeOf(linux.nlmsghdr) - 1),
        .type = .RTM_NEWLINK,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));
    try std.testing.expectError(error.InvalidResponse, parseLinkMessage(std.testing.allocator, &buff, hdr));
}

test "parseLinkMessage rejects malformed attribute length" {
    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg) + @sizeOf(linux.rtattr);
    var buff: [total_len]u8 = [_]u8{0} ** total_len;

    const hdr = linux.nlmsghdr{
        .len = @intCast(total_len),
        .type = .RTM_NEWLINK,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));

    const ifi = linux.ifinfomsg{
        .family = linux.AF.UNSPEC,
        .type = 0,
        .index = 1,
        .flags = 0,
        .change = 0,
    };
    const ifi_off = @sizeOf(linux.nlmsghdr);
    @memcpy(buff[ifi_off .. ifi_off + @sizeOf(linux.ifinfomsg)], std.mem.asBytes(&ifi));

    const attr = linux.rtattr{ .len = @intCast(@sizeOf(linux.rtattr) - 1), .type = .{ .link = .IFNAME } };
    const attr_off = ifi_off + @sizeOf(linux.ifinfomsg);
    @memcpy(buff[attr_off .. attr_off + @sizeOf(linux.rtattr)], std.mem.asBytes(&attr));

    try std.testing.expectError(error.InvalidResponse, parseLinkMessage(std.testing.allocator, &buff, hdr));
}

test "parseLinkMessage rejects attribute overrunning frame" {
    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg) + @sizeOf(linux.rtattr);
    var buff: [total_len]u8 = [_]u8{0} ** total_len;

    const hdr = linux.nlmsghdr{
        .len = @intCast(total_len),
        .type = .RTM_NEWLINK,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));

    const ifi = linux.ifinfomsg{
        .family = linux.AF.UNSPEC,
        .type = 0,
        .index = 1,
        .flags = 0,
        .change = 0,
    };
    const ifi_off = @sizeOf(linux.nlmsghdr);
    @memcpy(buff[ifi_off .. ifi_off + @sizeOf(linux.ifinfomsg)], std.mem.asBytes(&ifi));

    const attr = linux.rtattr{ .len = @intCast(@sizeOf(linux.rtattr) + 8), .type = .{ .link = .IFNAME } };
    const attr_off = ifi_off + @sizeOf(linux.ifinfomsg);
    @memcpy(buff[attr_off .. attr_off + @sizeOf(linux.rtattr)], std.mem.asBytes(&attr));

    try std.testing.expectError(error.InvalidResponse, parseLinkMessage(std.testing.allocator, &buff, hdr));
}

test "parseLinkMessage repeated parse/deinit does not leak" {
    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg);
    var buff: [total_len]u8 = [_]u8{0} ** total_len;

    const hdr = linux.nlmsghdr{
        .len = @intCast(total_len),
        .type = .RTM_NEWLINK,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));

    const ifi = linux.ifinfomsg{
        .family = linux.AF.UNSPEC,
        .type = 0,
        .index = 7,
        .flags = 0,
        .change = 0,
    };
    const ifi_off = @sizeOf(linux.nlmsghdr);
    @memcpy(buff[ifi_off .. ifi_off + @sizeOf(linux.ifinfomsg)], std.mem.asBytes(&ifi));

    var i: usize = 0;
    while (i < 128) : (i += 1) {
        var parsed = try parseLinkMessage(std.testing.allocator, &buff, hdr);
        parsed.deinit();
    }
}

test "parseLinkMessage rejects non-null-terminated IFNAME payload" {
    const payload_len = 4;
    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg) + @sizeOf(linux.rtattr) + payload_len;
    var buff: [total_len]u8 = [_]u8{0} ** total_len;

    const hdr = linux.nlmsghdr{
        .len = @intCast(total_len),
        .type = .RTM_NEWLINK,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));

    const ifi = linux.ifinfomsg{
        .family = linux.AF.UNSPEC,
        .type = 0,
        .index = 1,
        .flags = 0,
        .change = 0,
    };
    const ifi_off = @sizeOf(linux.nlmsghdr);
    @memcpy(buff[ifi_off .. ifi_off + @sizeOf(linux.ifinfomsg)], std.mem.asBytes(&ifi));

    const attr = linux.rtattr{ .len = @intCast(@sizeOf(linux.rtattr) + payload_len), .type = .{ .link = .IFNAME } };
    const attr_off = ifi_off + @sizeOf(linux.ifinfomsg);
    @memcpy(buff[attr_off .. attr_off + @sizeOf(linux.rtattr)], std.mem.asBytes(&attr));
    buff[attr_off + @sizeOf(linux.rtattr) + 0] = 'e';
    buff[attr_off + @sizeOf(linux.rtattr) + 1] = 't';
    buff[attr_off + @sizeOf(linux.rtattr) + 2] = 'h';
    buff[attr_off + @sizeOf(linux.rtattr) + 3] = '0';

    try std.testing.expectError(error.InvalidResponse, parseLinkMessage(std.testing.allocator, &buff, hdr));
}
