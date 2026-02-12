const std = @import("std");
const log = std.log;
const linux = std.os.linux;
const link = @import("link.zig");
const addr = @import("address.zig");
const route = @import("route.zig");

const Self = @This();

fd: std.posix.socket_t,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) !Self {
    const fd = try std.posix.socket(linux.AF.NETLINK, linux.SOCK.RAW, linux.NETLINK.ROUTE);
    const kernel_addr = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    std.posix.bind(fd, @ptrCast(&kernel_addr), @sizeOf(@TypeOf(kernel_addr))) catch {
        std.posix.close(fd);
        return error.BindFailed;
    };

    return .{ .allocator = allocator, .fd = fd };
}

pub fn deinit(self: *Self) void {
    std.posix.close(self.fd);
}

pub fn send(self: *Self, msg: []const u8) !void {
    const sent = try std.posix.send(self.fd, msg, 0);
    if (sent != msg.len) return error.ShortWrite;
}

pub fn recv(self: *Self, buff: []u8) !usize {
    const n = try std.posix.recv(self.fd, buff, 0);
    if (n == 0) {
        return error.InvalidResponse;
    }
    return n;
}

pub fn recv_ack(self: *Self) !void {
    var buff: [512]u8 = std.mem.zeroes([512]u8);
    const n = try std.posix.recv(self.fd, &buff, 0);
    if (n < @sizeOf(linux.nlmsghdr)) {
        return error.InvalidResponse;
    }

    const header = std.mem.bytesAsValue(linux.nlmsghdr, buff[0..@sizeOf(linux.nlmsghdr)]);
    if (header.len < @sizeOf(linux.nlmsghdr) or header.len > n) return error.InvalidResponse;
    const frame = buff[0..header.len];
    if (header.type == .DONE) {
        return;
    } else if (header.type == .ERROR) { // ACK/NACK response
        const err_code = try parseNetlinkErrorCode(frame);
        return handle_ack_code(err_code);
    }

    return error.InvalidResponse;
}

pub const NlMsgError = struct {
    hdr: linux.nlmsghdr,
    err: i32,
    msg: linux.nlmsghdr,
};

pub fn handle_ack(msg: NlMsgError) !void {
    return handle_ack_code(msg.err);
}

pub fn handle_ack_code(err_code: i32) !void {
    const code: linux.E = @enumFromInt(-1 * err_code);
    if (code != .SUCCESS) {
        log.info("err: {}", .{code});
        return switch (code) {
            .EXIST => error.Exists,
            else => error.Error,
        };
    }
}

pub fn parseNetlinkErrorCode(frame: []const u8) !i32 {
    if (frame.len < @sizeOf(linux.nlmsghdr) + @sizeOf(i32)) return error.InvalidResponse;
    const err_ptr = std.mem.bytesAsValue(i32, frame[@sizeOf(linux.nlmsghdr) .. @sizeOf(linux.nlmsghdr) + @sizeOf(i32)]);
    return err_ptr.*;
}

pub fn linkAdd(self: *Self, options: link.LinkAdd.Options) !void {
    var la = link.LinkAdd.init(self.allocator, self, options);
    defer la.msg.deinit();
    return la.exec();
}

pub fn linkGet(self: *Self, options: link.LinkGet.Options) !link.LinkMessage {
    var lg = link.LinkGet.init(self.allocator, self, options);
    defer lg.msg.deinit();
    return lg.exec();
}

pub fn linkSet(self: *Self, options: link.LinkSet.Options) !void {
    var ls = link.LinkSet.init(self.allocator, self, options);
    defer ls.msg.deinit();
    try ls.exec();
}

pub fn linkDel(self: *Self, index: c_int) !void {
    var ls = link.LinkDelete.init(self.allocator, self, index);
    defer ls.msg.deinit();
    try ls.exec();
}

pub fn addrAdd(self: *Self, options: addr.AddrAdd.Options) !void {
    var a = addr.AddrAdd.init(self.allocator, self, options);
    defer a.msg.deinit();
    return a.exec();
}

pub fn routeAdd(self: *Self, options: route.RouteAdd.Options) !void {
    var ls = route.RouteAdd.init(self.allocator, self, options);
    defer ls.msg.deinit();
    try ls.exec();
}

/// get all ipv4 routes
pub fn routeGet(self: *Self) ![]route.RouteMessage {
    var ls = route.RouteGet.init(self.allocator, self);
    defer ls.msg.deinit();
    return ls.exec();
}

test "parseNetlinkErrorCode extracts errno field" {
    const len = @sizeOf(linux.nlmsghdr) + @sizeOf(i32);
    var buff: [len]u8 = [_]u8{0} ** len;

    const hdr = linux.nlmsghdr{
        .len = @intCast(len),
        .type = .ERROR,
        .flags = 0,
        .seq = 0,
        .pid = 0,
    };
    const errno_value: i32 = -@as(i32, @intFromEnum(linux.E.EXIST));

    @memcpy(buff[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&hdr));
    @memcpy(buff[@sizeOf(linux.nlmsghdr) .. @sizeOf(linux.nlmsghdr) + @sizeOf(i32)], std.mem.asBytes(&errno_value));

    try std.testing.expectEqual(errno_value, try parseNetlinkErrorCode(&buff));
}

test "parseNetlinkErrorCode rejects truncated frame" {
    var buff: [@sizeOf(linux.nlmsghdr)]u8 = [_]u8{0} ** @sizeOf(linux.nlmsghdr);
    try std.testing.expectError(error.InvalidResponse, parseNetlinkErrorCode(&buff));
}
