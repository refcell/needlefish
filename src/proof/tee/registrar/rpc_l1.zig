//! The registrar's L1 over JSON-RPC (base/base `TEEProverRegistryContractClient`,
//! `CertManagerContractClient`, `NitroValidatorContractClient` and `SimpleTxManager`):
//! `eth_call` reads of the registry and `CertManager`, the startup resolution of the
//! `CertManager` through `NITRO_VALIDATOR().certManager()`, and a blocking transactor over
//! the shared `submission.Sender` that polls receipts every `poll_interval_ms`.
//!
//! A JSON-RPC error on a warm-validation `eth_call` is a revert (`ContractReverted`);
//! transport failures and malformed answers are `ContractCall`. Sender failures map onto
//! base/base `TxManagerError::is_retryable`: estimation reverts are permanent, broadcast
//! errors (nonce, fees), transport failures and dropped transactions are retryable, and a
//! failed receipt is a revert.

const std = @import("std");
const assert = std.debug.assert;

const l1 = @import("l1.zig");
const planner = @import("planner.zig");
const signer_manager = @import("signer_manager.zig");
const clients = @import("../../rpc/clients.zig");
const abi = @import("../../contracts/abi.zig");
const registry_abi = @import("../../contracts/tee_prover_registry.zig");
const cert_manager_abi = @import("../../contracts/cert_manager.zig");
const submission = @import("../../submission/root.zig");

const Address = l1.Address;
const Hash = l1.Hash;

/// A warm-validation call: selector, three head words, two length words, the padded
/// certificate and empty hints.
const call_size_max: u32 = 4 + 5 * 32 + planner.attestation_size_max + 32;

pub const ResolveError = error{ ContractCall, ZeroAddress };
pub const submission_failure = submission.sender.Failure;

/// Maps a sender failure onto a transaction outcome.
pub fn tx_outcome(failure: submission.sender.Failure) l1.TxOutcome {
    return switch (failure) {
        .rpc_error => |rpc_error| switch (rpc_error.phase) {
            .estimate => .{ .failed = .{ .retryable = false } },
            .broadcast => .{ .failed = .{ .retryable = true } },
            .replay => .reverted,
        },
        .reverted => .reverted,
        .unavailable, .dropped => .{ .failed = .{ .retryable = true } },
    };
}

pub fn RpcChain(comptime EndpointType: type) type {
    return struct {
        const Self = @This();
        const Execution = clients.Execution(EndpointType);

        endpoint: *EndpointType,
        registry: Address,
        cert_manager: Address,
        calldata: [call_size_max]u8 = undefined,

        pub fn init(endpoint: *EndpointType, registry: Address, cert_manager: Address) Self {
            assert(!std.mem.allEqual(u8, &registry, 0));
            assert(!std.mem.allEqual(u8, &cert_manager, 0));
            return .{ .endpoint = endpoint, .registry = registry, .cert_manager = cert_manager };
        }

        /// The `CertManager` behind `registry`: `NITRO_VALIDATOR()`, then `certManager()`.
        pub fn resolve_cert_manager(
            endpoint: *EndpointType,
            registry: Address,
        ) ResolveError!Address {
            assert(!std.mem.allEqual(u8, &registry, 0));
            var buffer: [4]u8 = undefined;
            const execution: Execution = .{ .endpoint = endpoint };
            endpoint.reset();
            const validator_function = registry_abi.nitro_validator;
            const validator_data = abi.encode_call(&buffer, validator_function, &.{}) catch
                unreachable; // Four bytes.
            const validator_raw = execution.call_contract(registry, validator_data, .latest) catch
                return error.ContractCall;
            const validator = registry_abi.decode_address(validator_raw) catch
                return error.ContractCall;
            if (std.mem.allEqual(u8, &validator, 0)) return error.ZeroAddress;
            endpoint.reset();
            const manager_data = abi.encode_call(&buffer, registry_abi.cert_manager, &.{}) catch
                unreachable; // Four bytes.
            const manager_raw = execution.call_contract(validator, manager_data, .latest) catch
                return error.ContractCall;
            const manager = registry_abi.decode_address(manager_raw) catch
                return error.ContractCall;
            if (std.mem.allEqual(u8, &manager, 0)) return error.ZeroAddress;
            return manager;
        }

        pub fn chain(self: *Self) l1.Chain {
            return .{ .context = self, .vtable = &vtable };
        }

        const vtable: l1.Chain.VTable = .{
            .is_registered_signer = is_registered_signer,
            .registered_signers = registered_signers,
            .load_verified = load_verified,
            .is_revoked = is_revoked,
            .verify_ca_cert = verify_ca_cert,
            .verify_client_cert = verify_client_cert,
        };

        fn of(context: *anyopaque) *Self {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(!std.mem.allEqual(u8, &self.registry, 0));
            return self;
        }

        /// One `eth_call` at the latest block; the return data lives until the next call.
        fn call(self: *Self, to: Address, data: []const u8) l1.CallError![]const u8 {
            assert(data.len >= 4);
            self.endpoint.reset();
            const execution: Execution = .{ .endpoint = self.endpoint };
            return execution.call_contract(to, data, .latest) catch |err| switch (err) {
                error.NotFound => if (self.endpoint.last_error != null)
                    error.ContractReverted
                else
                    error.ContractCall,
                error.CallFailed => error.ContractCall,
            };
        }

        fn read(self: *Self, to: Address, data: []const u8) l1.ReadError![]const u8 {
            return self.call(to, data) catch error.ContractCall;
        }

        fn is_registered_signer(context: *anyopaque, signer: Address) l1.ReadError!bool {
            const self = of(context);
            const function = registry_abi.is_registered_signer;
            const data = registry_abi.encode_signer_call(&self.calldata, function, signer) catch
                unreachable; // 36 bytes.
            const raw = try self.read(self.registry, data);
            return registry_abi.decode_bool(raw) catch error.ContractCall;
        }

        fn registered_signers(context: *anyopaque, out: []Address) l1.ReadError![]Address {
            const self = of(context);
            const function = registry_abi.get_registered_signers;
            const data = abi.encode_call(&self.calldata, function, &.{}) catch
                unreachable; // Four bytes.
            const raw = try self.read(self.registry, data);
            return registry_abi.decode_registered_signers(raw, out) catch error.ContractCall;
        }

        fn load_verified(context: *anyopaque, cert_hash: Hash) l1.ReadError!l1.CachedCert {
            const self = of(context);
            const function = cert_manager_abi.load_verified;
            const encode = cert_manager_abi.encode_hash_call;
            const data = encode(&self.calldata, function, cert_hash) catch
                unreachable; // 36 bytes.
            const raw = try self.read(self.cert_manager, data);
            const verified = cert_manager_abi.decode_verified_cert(raw) catch
                return error.ContractCall;
            return cached_cert(&verified);
        }

        fn is_revoked(context: *anyopaque, cert_id: Hash) l1.ReadError!bool {
            const self = of(context);
            const function = cert_manager_abi.is_revoked;
            const data = cert_manager_abi.encode_hash_call(&self.calldata, function, cert_id) catch
                unreachable; // 36 bytes.
            const raw = try self.read(self.cert_manager, data);
            return registry_abi.decode_bool(raw) catch error.ContractCall;
        }

        fn verify_ca_cert(
            context: *anyopaque,
            cert: []const u8,
            parent: Hash,
            hints: []const u8,
        ) l1.CallError!Hash {
            const self = of(context);
            const function = cert_manager_abi.verify_ca_cert_with_hints;
            const encode = cert_manager_abi.encode_verify;
            const data = encode(&self.calldata, function, cert, parent, hints) catch
                return error.ContractCall;
            const raw = try self.call(self.cert_manager, data);
            const decoder: abi.Decoder = .{ .data = raw };
            return (decoder.word(0) catch return error.ContractCall).*;
        }

        fn verify_client_cert(
            context: *anyopaque,
            cert: []const u8,
            parent: Hash,
            hints: []const u8,
        ) l1.CallError!l1.CachedCert {
            const self = of(context);
            const function = cert_manager_abi.verify_client_cert_with_hints;
            const encode = cert_manager_abi.encode_verify;
            const data = encode(&self.calldata, function, cert, parent, hints) catch
                return error.ContractCall;
            const raw = try self.call(self.cert_manager, data);
            const verified = cert_manager_abi.decode_verified_cert(raw) catch
                return error.ContractCall;
            return cached_cert(&verified);
        }
    };
}

fn cached_cert(verified: *const cert_manager_abi.VerifiedCert) l1.CachedCert {
    const result: l1.CachedCert = .{
        .ca = verified.ca,
        .not_after = verified.not_after,
        .has_public_key = verified.public_key.len > 0,
    };
    assert(result.has_public_key == (verified.public_key.len > 0));
    return result;
}

/// Advances time by `ms` while IO runs (the binary runs its event loop).
pub const Waiter = struct {
    context: *anyopaque,
    wait_ms: *const fn (context: *anyopaque, ms: u64) void,
};

pub fn RpcTransactor(comptime EndpointType: type) type {
    return struct {
        const Self = @This();
        const Sender = submission.Sender(EndpointType);

        sender: Sender,
        waiter: Waiter,
        poll_interval_ms: u64,

        pub fn init(
            allocator: std.mem.Allocator,
            endpoint: *EndpointType,
            config: submission.sender.Config,
            waiter: Waiter,
            poll_interval_ms: u64,
        ) !Self {
            assert(poll_interval_ms > 0);
            assert(config.calldata_bytes_max >= signer_manager.calldata_size_max);
            const sender = try Sender.init(allocator, endpoint, config);
            return .{ .sender = sender, .waiter = waiter, .poll_interval_ms = poll_interval_ms };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.sender.deinit(allocator);
            self.* = undefined;
        }

        pub fn transactor(self: *Self) l1.Transactor {
            return .{ .context = self, .send_fn = send };
        }

        /// Broadcasts, then polls the receipt until mined, failed or dropped (the sender
        /// drops it after `receipt_polls_max` polls).
        fn send(context: *anyopaque, to: Address, calldata: []const u8) l1.TxOutcome {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(calldata.len >= 4);
            const sent = self.sender.send(.{ .to = to, .value = 0, .calldata = calldata });
            const id = switch (sent) {
                .pending => |id| id,
                .failed => |failure| return tx_outcome(failure),
            };
            var polls: u32 = 0;
            while (polls <= self.sender.config.receipt_polls_max) : (polls += 1) {
                self.waiter.wait_ms(self.waiter.context, self.poll_interval_ms);
                switch (self.sender.status(id)) {
                    .pending => {},
                    .mined => return .succeeded,
                    .failed => |failure| return tx_outcome(failure),
                }
            }
            return .{ .failed = .{ .retryable = true } };
        }
    };
}

test {
    _ = @import("rpc_l1_test.zig");
}
