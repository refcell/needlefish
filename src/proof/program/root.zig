//! `proof/program`: the fault-proof program's boot inputs and the oracle-backed chain
//! providers it feeds into derivation. Port of base/base `crates/proof/proof`.

const std = @import("std");

pub const boot = @import("boot.zig");
pub const eip2935 = @import("eip2935.zig");
pub const hint = @import("hint.zig");
pub const intermediate_roots = @import("intermediate_roots.zig");
pub const l1_chain_provider = @import("l1_chain_provider.zig");
pub const l1_blob_provider = @import("l1_blob_provider.zig");
pub const l2_chain_provider = @import("l2_chain_provider.zig");
pub const schedule_id = @import("schedule_id.zig");
pub const sync = @import("sync.zig");

pub const BootInfo = boot.BootInfo;
pub const HintType = hint.HintType;
pub const IntermediateRootSampler = intermediate_roots.Sampler;
pub const L1ChainProvider = l1_chain_provider.L1ChainProvider;
pub const L1BlobProvider = l1_blob_provider.L1BlobProvider;
pub const L2ChainProvider = l2_chain_provider.L2ChainProvider;

test {
    std.testing.refAllDecls(@This());
    _ = @import("l1_chain_provider_test.zig");
    _ = @import("l2_chain_provider_test.zig");
}
