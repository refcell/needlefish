//! `proof/preimage`: preimage keys, the preimage oracle and hint protocols, and the
//! byte channel they run over. Port of base/base `crates/proof/preimage`.

const std = @import("std");

pub const key = @import("key.zig");
pub const channel = @import("channel.zig");
pub const oracle = @import("oracle.zig");
pub const hint = @import("hint.zig");
pub const in_process = @import("in_process.zig");

pub const Key = key.Key;
pub const KeyType = key.KeyType;
pub const Channel = channel.Channel;
pub const Duplex = channel.Duplex;
pub const Pump = channel.Pump;
pub const OracleReader = oracle.OracleReader;
pub const OracleServer = oracle.OracleServer;
pub const Fetcher = oracle.Fetcher;
pub const MemoryStore = oracle.MemoryStore;
pub const HintWriter = hint.HintWriter;
pub const HintReader = hint.HintReader;
pub const Router = hint.Router;
pub const Hint = hint.Hint;
pub const InProcess = in_process.InProcess;

test {
    std.testing.refAllDecls(@This());
}
