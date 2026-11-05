//! Derivation pipeline errors. base/base wraps every error in a kind: temporary (retry
//! later, usually waiting for L1 data), reset (rewind the pipeline to a safe L1 origin),
//! or critical (the pipeline cannot continue). Zig errors carry no payload, so the kind
//! is a pure function of the error value.
//! Mirrors base/base `crates/consensus/derive/src/errors/pipeline.rs`.

const std = @import("std");
const assert = std.debug.assert;

pub const Kind = enum { temporary, reset, critical };

/// Errors returned by chain and blob providers.
pub const ProviderError = error{
    /// The data is not available yet (fetch in flight, or not yet produced). Retry.
    NotAvailable,
    /// The block or receipt is unknown to the provider. Treated as temporary, like a
    /// provider that is behind the chain head.
    NotFound,
    /// The beacon node permanently lacks the blobs (missed or orphaned slot).
    BlobsUnavailable,
    OutOfMemory,
};

pub const Error = ProviderError || error{
    // Temporary.
    Eof,
    NotEnoughData,
    MissingL1Data,
    // Reset.
    ReorgDetected,
    HoloceneActivation,
    BadParentHash,
    BadTimestamp,
    L1OriginMismatch,
    NextL1BlockHashMismatch,
    BlobsUnderFill,
    BlobsOverFill,
    // Critical.
    MissingOrigin,
    ChannelProviderEmpty,
    ChannelNotFound,
    InvalidBatchType,
    InvalidBatchValidity,
    AttributesBuilder,
};

pub fn kind(err: Error) Kind {
    return switch (err) {
        error.NotAvailable,
        error.NotFound,
        error.Eof,
        error.NotEnoughData,
        error.MissingL1Data,
        => .temporary,
        error.ReorgDetected,
        error.HoloceneActivation,
        error.BadParentHash,
        error.BadTimestamp,
        error.L1OriginMismatch,
        error.NextL1BlockHashMismatch,
        error.BlobsUnavailable,
        error.BlobsUnderFill,
        error.BlobsOverFill,
        => .reset,
        error.OutOfMemory,
        error.MissingOrigin,
        error.ChannelProviderEmpty,
        error.ChannelNotFound,
        error.InvalidBatchType,
        error.InvalidBatchValidity,
        error.AttributesBuilder,
        => .critical,
    };
}

test "errors: kinds" {
    try std.testing.expectEqual(Kind.temporary, kind(error.Eof));
    try std.testing.expectEqual(Kind.temporary, kind(error.NotAvailable));
    try std.testing.expectEqual(Kind.reset, kind(error.BlobsUnavailable));
    try std.testing.expectEqual(Kind.reset, kind(error.HoloceneActivation));
    try std.testing.expectEqual(Kind.critical, kind(error.OutOfMemory));
    assert(kind(error.MissingOrigin) == .critical);
}
