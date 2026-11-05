//! Consensus types for Base: transactions (all EIP-2718 types incl. OP deposits),
//! signatures and sender recovery. Mirrors base/base `crates/common/consensus`.

const std = @import("std");

pub const signature = @import("signature.zig");
pub const tx_fields = @import("tx_fields.zig");
pub const tx = @import("tx.zig");
pub const hashing = @import("hashing.zig");
pub const header = @import("header.zig");
pub const receipt = @import("receipt.zig");
pub const block = @import("block.zig");
pub const sidecar = @import("sidecar.zig");
pub const item_list = @import("item_list.zig");
pub const predeploys = @import("predeploys.zig");
pub const base_time = @import("base_time.zig");
pub const bench = @import("bench.zig");
pub const eip8130 = @import("eip8130.zig");
pub const eip8130_structure = @import("eip8130_structure.zig");
pub const eip8130_gas = @import("eip8130_gas.zig");
pub const eip8130_test = @import("eip8130_test.zig");

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
pub const Sidecar = sidecar.Sidecar;
pub const PooledBlobTx = sidecar.PooledBlobTx;
pub const PooledTx = sidecar.PooledTx;
pub const Header = header.Header;
pub const Receipt = receipt.Receipt;
pub const Log = receipt.Log;
pub const Logs = receipt.Logs;
pub const Block = block.Block;
pub const Body = block.Body;
pub const Withdrawal = block.Withdrawal;

test {
    std.testing.refAllDecls(@This());
    _ = @import("tx_test.zig");
}
