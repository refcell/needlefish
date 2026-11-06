//! The onchain `TEEProverRegistry` behind `registration.Registry` (base/base
//! `TEEProverRegistryContractClient`): `isValidSigner` and `signerImageHash` as `eth_call`s at
//! the latest block, over any endpoint with `proof/rpc` `Endpoint`'s call shape.

const std = @import("std");
const assert = std.debug.assert;

const registration = @import("registration.zig");
const clients = @import("../../rpc/clients.zig");
const registry_abi = @import("../../contracts/tee_prover_registry.zig");
const abi = @import("../../contracts/abi.zig");

const Address = [20]u8;
const Hash = [32]u8;
const RegistryError = registration.RegistryError;

pub fn RpcRegistry(comptime EndpointType: type) type {
    return struct {
        const Self = @This();
        const Execution = clients.Execution(EndpointType);

        endpoint: *EndpointType,
        address: Address,
        calldata: [36]u8 = undefined,

        pub fn init(endpoint: *EndpointType, address: Address) Self {
            assert(!std.mem.allEqual(u8, &address, 0));
            const self: Self = .{ .endpoint = endpoint, .address = address };
            assert(self.endpoint == endpoint);
            return self;
        }

        pub fn registry(self: *Self) registration.Registry {
            return .{ .context = self, .vtable = &vtable };
        }

        const vtable: registration.Registry.VTable = .{
            .is_valid_signer = is_valid_signer,
            .signer_image_hash = signer_image_hash,
        };

        fn call(self: *Self, function: [4]u8, signer: Address) RegistryError![]const u8 {
            const data = registry_abi.encode_signer_call(&self.calldata, function, signer) catch
                unreachable; // Selector plus one word fits the 36-byte buffer.
            assert(data.len == 36);
            self.endpoint.reset();
            const execution: Execution = .{ .endpoint = self.endpoint };
            return execution.call_contract(self.address, data, .latest) catch
                error.RegistryUnavailable;
        }

        fn is_valid_signer(context: *anyopaque, signer: Address) RegistryError!bool {
            const self: *Self = @ptrCast(@alignCast(context));
            const raw = try self.call(registry_abi.is_valid_signer, signer);
            return registry_abi.decode_bool(raw) catch error.RegistryUnavailable;
        }

        fn signer_image_hash(context: *anyopaque, signer: Address) RegistryError!Hash {
            const self: *Self = @ptrCast(@alignCast(context));
            const raw = try self.call(registry_abi.signer_image_hash, signer);
            const decoder: abi.Decoder = .{ .data = raw };
            const word = decoder.word(0) catch return error.RegistryUnavailable;
            return word.*;
        }
    };
}

const testing = std.testing;
const Param = @import("../../rpc/endpoint.zig").Param;

/// Answers `eth_call` with one canned return word and records the calldata.
const FakeEndpoint = struct {
    answer: []const u8 = "",
    fail: bool = false,
    to: Address = @splat(0),
    data: [36]u8 = @splat(0),

    pub fn reset(endpoint: *FakeEndpoint) void {
        assert(endpoint.answer.len <= 66);
    }

    pub fn call(
        endpoint: *FakeEndpoint,
        method: []const u8,
        params: []const Param,
    ) error{ NotFound, CallFailed }![]const u8 {
        assert(std.mem.eql(u8, method, "eth_call"));
        endpoint.to = params[0].call.to;
        @memcpy(&endpoint.data, params[0].call.data[0..36]);
        if (endpoint.fail) return error.CallFailed;
        return endpoint.answer;
    }

    pub fn hex(endpoint: *FakeEndpoint, raw: []const u8) error{CallFailed}![]const u8 {
        _ = endpoint;
        return raw;
    }
};

test "tee rpc registry: validity and image hash through eth_call" {
    var endpoint: FakeEndpoint = .{};
    var true_word: [32]u8 = @splat(0);
    true_word[31] = 1;
    endpoint.answer = &true_word;
    const address: Address = @splat(0xa5);
    var rpc_registry: RpcRegistry(FakeEndpoint) = .init(&endpoint, address);
    const registry = rpc_registry.registry();
    const signer: Address = @splat(0x11);
    try testing.expect(try registry.is_valid_signer(signer));
    try testing.expectEqual(address, endpoint.to);
    try testing.expectEqualSlices(u8, &registry_abi.is_valid_signer, endpoint.data[0..4]);
    try testing.expectEqualSlices(u8, &signer, endpoint.data[16..36]);
    const image: [32]u8 = @splat(0x77);
    endpoint.answer = &image;
    try testing.expectEqual(image, try registry.signer_image_hash(signer));
    // A word that is not a bool, a short answer, and a failed call are all unavailable.
    try testing.expectError(error.RegistryUnavailable, registry.is_valid_signer(signer));
    endpoint.answer = "short";
    try testing.expectError(error.RegistryUnavailable, registry.signer_image_hash(signer));
    endpoint.fail = true;
    try testing.expectError(error.RegistryUnavailable, registry.is_valid_signer(signer));
}
