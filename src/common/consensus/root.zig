//! Consensus types for Base: transactions (all EIP-2718 types incl. OP deposits),
//! signatures and sender recovery. Mirrors base/base `crates/common/consensus`.

const std = @import("std");

pub const signature = @import("signature.zig");
pub const tx_fields = @import("tx_fields.zig");
pub const tx = @import("tx.zig");

pub const Signature = signature.Signature;
pub const Recoverer = signature.Recoverer;
pub const recover_address = signature.recover_address;
pub const TxType = tx.TxType;
pub const TxKind = tx.TxKind;
pub const AccessList = tx.AccessList;
pub const AuthorizationList = tx.AuthorizationList;
pub const Authorization = tx_fields.Authorization;
pub const HashList = tx.HashList;
pub const Legacy = tx.Legacy;
pub const Eip2930 = tx.Eip2930;
pub const Eip1559 = tx.Eip1559;
pub const Eip4844 = tx.Eip4844;
pub const Eip7702 = tx.Eip7702;
pub const Deposit = tx.Deposit;
pub const Envelope = tx.Envelope;
pub const Signed = tx.Signed;

test {
    std.testing.refAllDecls(@This());
    _ = @import("tx_test.zig");
}
