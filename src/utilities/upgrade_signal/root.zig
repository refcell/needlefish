//! Network upgrade activation signals read from L1 (base/base `upgrade-signal`).
//!
//! Ported: packed protocol versions, the `ProtocolVersions` contract ABI (strict decoding),
//! contract-backed upgrade IDs, public default contract addresses, and an IO-driven schedule
//! reader. Applying a schedule (metrics-only / startup-apply / runtime-admin) belongs to the
//! execution and consensus lanes, which map `upgrade_ids` onto their own upgrade enums.

pub const version = @import("version.zig");
pub const Version = version.Version;
pub const contract = @import("contract.zig");
pub const reader = @import("reader.zig");
pub const Reader = reader.Reader;
pub const Schedule = reader.Schedule;
pub const BlockTag = reader.BlockTag;

test {
    _ = version;
    _ = contract;
    _ = reader;
    _ = @import("tests.zig");
}
