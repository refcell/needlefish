//! `proof/program`: the fault-proof program's boot inputs and the oracle-backed chain
//! providers it feeds into derivation. Port of base/base `crates/proof/proof`.

const std = @import("std");

pub const boot = @import("boot.zig");
pub const hint = @import("hint.zig");
pub const l1_chain_provider = @import("l1_chain_provider.zig");
pub const l1_blob_provider = @import("l1_blob_provider.zig");

pub const BootInfo = boot.BootInfo;
pub const HintType = hint.HintType;
pub const L1ChainProvider = l1_chain_provider.L1ChainProvider;
pub const L1BlobProvider = l1_blob_provider.L1BlobProvider;

test {
    std.testing.refAllDecls(@This());
    _ = @import("l1_chain_provider_test.zig");
}
