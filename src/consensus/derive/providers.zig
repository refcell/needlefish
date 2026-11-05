//! Data the pipeline needs from the outside world.
//!
//! Stages are generic over a provider type (`anytype`), so the node, the fault-proof
//! program, the deterministic simulator, and tests each plug in their own. Providers
//! must never block: when data is still being fetched they return
//! `error.NotAvailable`, the pipeline step fails temporarily, and the driver retries
//! after the IO completes.
//!
//! A chain provider implements:
//!   fn l1_block_info_by_number(self, number: u64) ProviderError!BlockInfo
//!   fn l1_receipts_by_hash(self, hash: Hash) ProviderError![]const Receipt
//!   fn l1_transactions_by_hash(self, hash: Hash) ProviderError![]const L1Transaction
//! A blob provider implements:
//!   fn blobs(self, block: BlockInfo, hashes: []const Hash) ProviderError![]const *const Blob
//! Returned slices only need to stay valid until the next call on the same provider:
//! stages copy what they keep.

const primitives = @import("../../common/primitives/root.zig");

/// An L1 transaction as seen by the data sources.
pub const L1Transaction = struct {
    /// EIP-2718 type (0 for legacy). Unknown types are ignored by the data sources.
    tx_type: u8,
    /// Null for contract creations.
    to: ?primitives.Address,
    /// The recovered sender. Providers backed by an untrusted RPC must recover it from the
    /// signature rather than trust the `from` field.
    from: primitives.Address,
    input: []const u8,
    blob_hashes: []const primitives.B256 = &.{},

    pub const type_legacy: u8 = 0;
    pub const type_eip2930: u8 = 1;
    pub const type_eip1559: u8 = 2;
    pub const type_eip4844: u8 = 3;
};
