//! Public consensus-layer boot nodes for Base networks, copied from base/base
//! `crates/common/chains/src/config.rs` (`bootnodes.consensus`). Parsed lazily; the
//! test below checks every record decodes, verifies, and advertises its chain id.

const std = @import("std");
const assert = std.debug.assert;
const enr = @import("enr.zig");
const enode = @import("enode.zig");
const multiaddr = @import("multiaddr.zig");

pub const mainnet_chain_id = 8453;
pub const sepolia_chain_id = 84532;
pub const zeronet_chain_id = 763360;

pub const mainnet = [_][]const u8{
    \\enr:-J24QNz9lbrKbN4iSmmjtnr7SjUMk4zB7f1krHZcTZx-JRKZd0kA2gjufUROD6T3sOWDVDnFJRvqBBo62zuF-hYCohOGAYiOoEyEgmlkgnY0gmlwhAPniryHb3BzdGFja4OFQgCJc2VjcDI1NmsxoQKNVFlCxh_B-716tTs-h1vMzZkSs1FTu_OYTNjgufplG4N0Y3CCJAaDdWRwgiQG
    ,
    \\enr:-J24QH-f1wt99sfpHy4c0QJM-NfmsIfmlLAMMcgZCUEgKG_BBYFc6FwYgaMJMQN5dsRBJApIok0jFn-9CS842lGpLmqGAYiOoDRAgmlkgnY0gmlwhLhIgb2Hb3BzdGFja4OFQgCJc2VjcDI1NmsxoQJ9FTIv8B9myn1MWaC_2lJ-sMoeCDkusCsk4BYHjjCq04N0Y3CCJAaDdWRwgiQG
    ,
    \\enr:-J24QDXyyxvQYsd0yfsN0cRr1lZ1N11zGTplMNlW4xNEc7LkPXh0NAJ9iSOVdRO95GPYAIc6xmyoCCG6_0JxdL3a0zaGAYiOoAjFgmlkgnY0gmlwhAPckbGHb3BzdGFja4OFQgCJc2VjcDI1NmsxoQJwoS7tzwxqXSyFL7g0JM-KWVbgvjfB8JA__T7yY_cYboN0Y3CCJAaDdWRwgiQG
    ,
    \\enr:-J24QHmGyBwUZXIcsGYMaUqGGSl4CFdx9Tozu-vQCn5bHIQbR7On7dZbU61vYvfrJr30t0iahSqhc64J46MnUO2JvQaGAYiOoCKKgmlkgnY0gmlwhAPnCzSHb3BzdGFja4OFQgCJc2VjcDI1NmsxoQINc4fSijfbNIiGhcgvwjsjxVFJHUstK9L1T8OTKUjgloN0Y3CCJAaDdWRwgiQG
    ,
    \\enr:-J24QG3ypT4xSu0gjb5PABCmVxZqBjVw9ca7pvsI8jl4KATYAnxBmfkaIuEqy9sKvDHKuNCsy57WwK9wTt2aQgcaDDyGAYiOoGAXgmlkgnY0gmlwhDbGmZaHb3BzdGFja4OFQgCJc2VjcDI1NmsxoQIeAK_--tcLEiu7HvoUlbV52MspE0uCocsx1f_rYvRenIN0Y3CCJAaDdWRwgiQG
    ,
};

pub const sepolia = [_][]const u8{
    \\enr:-J64QFa3qMsONLGphfjEkeYyF6Jkil_jCuJmm7_a42ckZeUQGLVzrzstZNb1dgBp1GGx9bzImq5VxJLP-BaptZThGiWGAYrTytOvgmlkgnY0gmlwhGsV-zeHb3BzdGFja4S0lAUAiXNlY3AyNTZrMaEDahfSECTIS_cXyZ8IyNf4leANlZnrsMEWTkEYxf4GMCmDdGNwgiQGg3VkcIIkBg
    ,
    \\enr:-J64QBwRIWAco7lv6jImSOjPU_W266lHXzpAS5YOh7WmgTyBZkgLgOwo_mxKJq3wz2XRbsoBItbv1dCyjIoNq67mFguGAYrTxM42gmlkgnY0gmlwhBLSsHKHb3BzdGFja4S0lAUAiXNlY3AyNTZrMaEDmoWSi8hcsRpQf2eJsNUx-sqv6fH4btmo2HsAzZFAKnKDdGNwgiQGg3VkcIIkBg
    ,
};

pub const zeronet = [_][]const u8{
    \\enr:-Ji4QLr5n2VbXQohRywhyi2_efPpMcKzKL7DtllVNgkn_fDuGszrobGsTjM9WX7TxVqbW6YX8pxEx7lmvHprVc3HX8wBgmlkgnY0gmlwhDZaa-CHb3BzdGFja4Tgyy4AiXNlY3AyNTZrMaEDG1GmDUlW2vWzc7QQ_QOgPFG1Gfn-sCC8FQTef-GdCo2DdGNwgiQGg3VkcIIkBg
    ,
};

pub const Error = error{ InvalidText, UnknownChain } || enr.Error || enode.Error;

/// Boot node ENR strings for a chain id, or an empty list for unknown chains.
pub fn for_chain(chain_id: u64) []const []const u8 {
    comptime assert(mainnet.len > 0 and sepolia.len > 0 and zeronet.len > 0);
    return switch (chain_id) {
        mainnet_chain_id => &mainnet,
        sepolia_chain_id => &sepolia,
        zeronet_chain_id => &zeronet,
        else => &.{},
    };
}

/// A parsed boot node (base/base `BootNode`): either a signed record or an enode URL.
pub const BootNode = union(enum) {
    record: enr.Record,
    enode: enode.NodeRecord,

    /// Dialable TCP multiaddr with peer id, or null if the record has no TCP socket.
    pub fn to_multiaddr(node: *const BootNode) ?multiaddr.Multiaddr {
        return switch (node.*) {
            .record => |*record| multiaddr.from_enr(record),
            .enode => |*record| record.to_multiaddr(),
        };
    }
};

/// Parses `enr:` or `enode://` text (base/base `BootNode::parse_bootnode`).
pub fn parse(text: []const u8) Error!BootNode {
    if (std.mem.startsWith(u8, text, enr.text_prefix)) {
        const record = try enr.decode_text(text);
        assert(record.length <= enr.size_max);
        return .{ .record = record };
    }
    if (std.mem.startsWith(u8, text, enode.scheme)) return .{ .enode = try enode.parse(text) };
    return error.InvalidText;
}

test "boot: every public record verifies and matches its chain" {
    const chains = [_]u64{ mainnet_chain_id, sepolia_chain_id, zeronet_chain_id };
    const counts = [_]usize{ 5, 2, 1 };
    for (chains, counts) |chain_id, count| {
        const list = for_chain(chain_id);
        try std.testing.expectEqual(count, list.len);
        for (list) |text| {
            const node = try parse(text);
            const record = &node.record;
            try std.testing.expectEqual(enr.Validation.valid, enr.validate_chain(record, chain_id));
            try std.testing.expectEqual(@as(?u16, 9222), record.tcp());
            try std.testing.expect(node.to_multiaddr() != null);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), for_chain(0).len);
}

test "boot: parse dispatch" {
    try std.testing.expectError(error.InvalidText, parse("garbage"));
    try std.testing.expectError(error.InvalidText, parse("enr:invalid!"));
    try std.testing.expectError(error.InvalidText, parse("enode://invalid@127.0.0.1:30303"));
}
