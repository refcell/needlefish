//! `TEEProverRegistry` and `NitroValidator` calls (base/base
//! `crates/proof/contracts/src/{tee_prover_registry,nitro_validator}.rs`): hinted signer
//! registration, deregistration and the registration reads the registrar and proposer use.

const std = @import("std");
const assert = std.debug.assert;

const abi = @import("abi.zig");

const Address = abi.Address;

pub const nitro_validator = abi.selector("NITRO_VALIDATOR()");
pub const register_signer = abi.selector("registerSigner(bytes,bytes,bytes)");
pub const deregister_signer = abi.selector("deregisterSigner(address)");
pub const is_valid_signer = abi.selector("isValidSigner(address)");
pub const is_registered_signer = abi.selector("isRegisteredSigner(address)");
pub const signer_image_hash = abi.selector("signerImageHash(address)");
pub const get_registered_signers = abi.selector("getRegisteredSigners()");
/// `NitroValidator.certManager()`.
pub const cert_manager = abi.selector("certManager()");

/// Upper bound on the registered signers one read returns.
pub const registered_signers_max = 1024;

pub fn encode_register_signer(
    out: []u8,
    attestation_tbs: []const u8,
    signature: []const u8,
    hints: []const u8,
) abi.EncodeError![]u8 {
    assert(signature.len > 0);
    return abi.encode_call(out, register_signer, &.{
        .{ .bytes = attestation_tbs }, .{ .bytes = signature }, .{ .bytes = hints },
    });
}

/// `deregisterSigner`, `isValidSigner`, `isRegisteredSigner` and `signerImageHash`.
pub fn encode_signer_call(out: []u8, function: [4]u8, signer: Address) abi.EncodeError![]u8 {
    assert(std.mem.eql(u8, &function, &deregister_signer) or
        std.mem.eql(u8, &function, &is_valid_signer) or
        std.mem.eql(u8, &function, &is_registered_signer) or
        std.mem.eql(u8, &function, &signer_image_hash));
    return abi.encode_call(out, function, &.{.{ .address = signer }});
}

/// The `address[]` returned by `getRegisteredSigners()`, copied into `out`.
pub fn decode_registered_signers(data: []const u8, out: []Address) abi.DecodeError![]Address {
    const decoder: abi.Decoder = .{ .data = data };
    const offset = try decoder.uint(u32, 0);
    if (offset % 32 != 0) return error.TypeCheck;
    const length = try decoder.uint(u32, offset / 32);
    if (length > out.len) return error.Overrun;
    const items: abi.Decoder = .{ .data = data[offset + 32 ..] };
    for (out[0..length], 0..) |*signer, index| signer.* = try items.address(index);
    assert(length <= out.len);
    return out[0..length];
}

/// A single `address` return (`NITRO_VALIDATOR()`, `certManager()`).
pub fn decode_address(data: []const u8) abi.DecodeError!Address {
    const decoder: abi.Decoder = .{ .data = data };
    return decoder.address(0);
}

/// A single `bool` return (`isValidSigner`, `isRegisteredSigner`).
pub fn decode_bool(data: []const u8) abi.DecodeError!bool {
    const decoder: abi.Decoder = .{ .data = data };
    return decoder.boolean(0);
}

const testing = std.testing;

test "tee prover registry: selectors, calls and returns" {
    try testing.expect(!std.mem.eql(u8, &register_signer, &deregister_signer));
    var buffer: [512]u8 = undefined;
    const tbs: [40]u8 = @splat(1);
    const call = try encode_register_signer(&buffer, &tbs, &(@as([96]u8, @splat(2))), "");
    const decoder = try abi.Decoder.call(call, register_signer);
    try testing.expectEqualSlices(u8, &tbs, try decoder.bytes(0));
    try testing.expectEqual(@as(usize, 96), (try decoder.bytes(1)).len);
    try testing.expectEqual(@as(usize, 0), (try decoder.bytes(2)).len);
    const signer: Address = @splat(0xaa);
    const deregister = try encode_signer_call(&buffer, deregister_signer, signer);
    const args = try abi.Decoder.call(deregister, deregister_signer);
    try testing.expectEqual(signer, try args.address(0));

    var data: [32 * 4]u8 = @splat(0);
    data[31] = 32;
    data[63] = 2;
    data[64 + 12 ..][0..20].* = @splat(0x11);
    data[96 + 12 ..][0..20].* = @splat(0x22);
    var signers: [4]Address = undefined;
    const decoded = try decode_registered_signers(&data, &signers);
    try testing.expectEqual(@as(usize, 2), decoded.len);
    try testing.expectEqual(@as(Address, @splat(0x22)), decoded[1]);
    try testing.expectError(error.Overrun, decode_registered_signers(&data, signers[0..1]));
    data[64] = 1;
    try testing.expectError(error.TypeCheck, decode_registered_signers(&data, &signers));
    // A bool word above one is not a bool.
    try testing.expectError(error.TypeCheck, decode_bool(data[32..64]));
}

test "tee prover registry: fuzz return decoders stay in bounds" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var data: [160]u8 = undefined;
            const length = smith.index(data.len);
            smith.bytes(data[0..length]);
            var signers: [3]Address = undefined;
            if (decode_registered_signers(data[0..length], &signers)) |decoded| {
                try testing.expect(decoded.len <= signers.len);
            } else |_| {}
            _ = decode_address(data[0..length]) catch {};
        }
    }.one, .{ .iterations = 3000 });
}
