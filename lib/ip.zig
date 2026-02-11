const std = @import("std");

pub fn getContainerIpv4Addr(container_id: []const u8) [4]u8 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(container_id);
    const hash = hasher.final();

    // 10.0.0.1 is reserved for the bridge gateway.
    const host_octet: u8 = @intCast((hash % 253) + 2);
    return .{ 10, 0, 0, host_octet };
}

test "getContainerIpv4Addr is deterministic per container id" {
    const a = getContainerIpv4Addr("container-a");
    const b = getContainerIpv4Addr("container-a");
    try std.testing.expectEqual(a, b);
}

test "getContainerIpv4Addr reserves network and gateway octets" {
    const addr = getContainerIpv4Addr("container-b");
    try std.testing.expectEqual(@as(u8, 10), addr[0]);
    try std.testing.expectEqual(@as(u8, 0), addr[1]);
    try std.testing.expectEqual(@as(u8, 0), addr[2]);
    try std.testing.expect(addr[3] >= 2 and addr[3] <= 254);
}
