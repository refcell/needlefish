//! Chain preparation before a load test (base/base `load-tests/src/workload/chain_prep.rs`
//! and `accounts.rs` funding): deploy the workload contracts from a funder account, check
//! their code, then fund every sender with ETH and mint it test tokens.
//!
//! One transaction-manager driver sends for the funder, with at most `in_flight_max`
//! unconfirmed transactions at a time (a sliding batch: a slot frees when its transaction
//! confirms). Any failed transaction fails the prep; the runner then reports and stops.
//! Contract addresses are `create_address(funder, nonce)` from each deploy's completion.
//! Like `Runner`, `Prep` is a sans-clock state machine driven by `step(client, now_ms)`.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const driver_module = @import("../tx_manager/driver.zig");
const manager = @import("../tx_manager/manager.zig");
const evm = @import("../../execution/evm/evm.zig");
const contracts = @import("contracts.zig");
const workload = @import("workload.zig");
const key_stream = @import("key_stream.zig");

const Address = workload.Address;
pub const Account = key_stream.Account;

pub const in_flight_limit = 32;
pub const senders_max = 256;
const Driver = driver_module.Driver(.{ .sends_max = in_flight_limit, .hashes_max = 8 });
const contract_kinds = std.enums.values(contracts.Kind);
const runtime_bytes_max = 1024;

pub const Config = struct {
    chain_id: u64,
    funder: Account,
    /// Wei sent to each sender; 0 skips funding (the senders already hold ETH).
    fund_wei: u256,
    /// Deploy the token, storage, and looper contracts first.
    deploy: bool = true,
    /// Tokens minted to each sender after deploying; 0 skips mints.
    mint_amount: u256 = 1_000_000_000_000_000_000_000_000,
    in_flight_max: u32 = 16,
    manager: manager.Config = .{},
};

pub const Phase = enum { deploy, verify, fund, done, failed };

const Item = union(enum) { deploy: contracts.Kind, fund: Address, mint: Address };
const Pending = struct { id: u64 = 0, item: Item = .{ .fund = .{ .bytes = @splat(0) } } };

pub const Prep = struct {
    config: Config,
    driver: Driver,
    senders: [senders_max]Address = undefined,
    sender_count: u32,
    phase: Phase,
    /// Items of the current phase: sent so far, confirmed so far, and total.
    sent: u32 = 0,
    confirmed: u32 = 0,
    items: u32 = 0,
    pending: [in_flight_limit]Pending = @splat(.{}),
    deployed: [contract_kinds.len]?Address = @splat(null),
    send_errors: u64 = 0,
    rpc_errors: u64 = 0,
    failure: ?manager.Failure = null,
    funded: u32 = 0,
    minted: u32 = 0,
    /// Every deployed contract holds the expected code.
    verified: bool = false,

    pub fn init(
        prep: *Prep,
        allocator: std.mem.Allocator,
        config: Config,
        senders: []const Address,
    ) !void {
        if (senders.len > senders_max) return error.InvalidSenderCount;
        if (config.in_flight_max == 0 or config.in_flight_max > in_flight_limit) {
            return error.InvalidConfig;
        }
        prep.* = .{
            .config = config,
            .driver = try Driver.init(allocator, .{
                .chain_id = config.chain_id,
                .private_key = config.funder.private_key,
                .from = config.funder.address,
                .data_bytes_max = runtime_bytes_max,
                .manager = config.manager,
            }),
            .sender_count = @intCast(senders.len),
            .phase = .deploy,
        };
        @memcpy(prep.senders[0..senders.len], senders);
        prep.enter(if (config.deploy) .deploy else .fund);
        assert(prep.phase != .verify);
    }

    pub fn deinit(prep: *Prep, allocator: std.mem.Allocator) void {
        prep.driver.deinit(allocator);
        prep.* = undefined;
    }

    pub fn done(prep: *const Prep) bool {
        return prep.phase == .done or prep.phase == .failed;
    }

    /// Deployed contract addresses; null until the deploy phase confirmed and verified.
    pub fn contracts_deployed(prep: *const Prep) ?workload.Contracts {
        if (!prep.verified) return null;
        assert(prep.config.deploy);
        return .{
            .token = prep.deployed[@backingInt(contracts.Kind.token)].?,
            .storage = prep.deployed[@backingInt(contracts.Kind.storage)].?,
            .looper = prep.deployed[@backingInt(contracts.Kind.looper)].?,
        };
    }

    fn enter(prep: *Prep, phase: Phase) void {
        prep.phase = phase;
        prep.sent = 0;
        prep.confirmed = 0;
        prep.items = switch (phase) {
            .deploy => contract_kinds.len,
            .fund => prep.sender_count * prep.items_per_sender(),
            .verify, .done, .failed => 0,
        };
        if (phase == .fund and prep.items == 0) prep.phase = .done;
        assert(prep.sent <= prep.items);
    }

    fn items_per_sender(prep: *const Prep) u32 {
        const mints = prep.config.deploy and prep.config.mint_amount > 0;
        const count = @as(u32, @intFromBool(prep.config.fund_wei > 0)) + @intFromBool(mints);
        assert(count <= 2);
        return count;
    }

    pub fn step(prep: *Prep, client: *rpc.Client, now_ms: u64) void {
        assert(prep.confirmed <= prep.sent and prep.sent <= prep.items);
        switch (prep.phase) {
            .done, .failed => return,
            .verify => return prep.verify(client),
            .deploy, .fund => {},
        }
        prep.send_due(client, now_ms);
        prep.driver.step(client, now_ms) catch {
            prep.rpc_errors += 1;
        };
        prep.collect();
        if (prep.phase == .failed or prep.confirmed < prep.items) return;
        prep.enter(if (prep.phase == .deploy) .verify else .done);
    }

    fn send_due(prep: *Prep, client: *rpc.Client, now_ms: u64) void {
        var mint_buffer: [68]u8 = undefined;
        while (prep.sent < prep.items) {
            if (prep.driver.manager.pending_count() >= prep.config.in_flight_max) return;
            const item = prep.item_at(prep.sent);
            const request = prep.candidate(item, &mint_buffer);
            const id = prep.driver.send(client, request, now_ms) catch {
                prep.send_errors += 1;
                return; // Retried on the next step.
            };
            prep.remember(id, item);
            prep.sent += 1;
        }
        assert(prep.sent == prep.items);
    }

    fn item_at(prep: *const Prep, index: u32) Item {
        assert(index < prep.items);
        if (prep.phase == .deploy) return .{ .deploy = contract_kinds[index] };
        assert(prep.phase == .fund);
        const per_sender = prep.items_per_sender();
        const sender = prep.senders[index / per_sender];
        const is_fund = prep.config.fund_wei > 0 and index % per_sender == 0;
        return if (is_fund) .{ .fund = sender } else .{ .mint = sender };
    }

    fn candidate(prep: *const Prep, item: Item, mint_buffer: *[68]u8) driver_module.Candidate {
        switch (item) {
            .deploy => |kind| return .{
                .to = null,
                .data = contracts.init_code_of(kind),
                .gas_limit = contracts.deploy_gas(kind),
            },
            .fund => |sender| return .{
                .to = sender,
                .value = prep.config.fund_wei,
                .gas_limit = 21_000,
            },
            .mint => |sender| {
                mint_buffer.* = contracts.selector_mint ++ word(address_int(sender)) ++
                    word(prep.config.mint_amount);
                return .{
                    .to = prep.deployed[@backingInt(contracts.Kind.token)].?,
                    .data = mint_buffer,
                    .gas_limit = txdata.calldata_gas(mint_buffer) + contracts.token_mint_gas,
                };
            },
        }
    }

    fn collect(prep: *Prep) void {
        while (prep.driver.take_completion()) |completion| {
            const pending = prep.forget(completion.id);
            switch (completion.outcome) {
                .failed => |failure| {
                    prep.failure = failure;
                    prep.phase = .failed;
                    continue;
                },
                .confirmed => prep.confirmed += 1,
            }
            switch (pending.item) {
                .deploy => |kind| {
                    const funder = prep.config.funder.address.bytes;
                    const created = evm.create_address(funder, completion.nonce);
                    prep.deployed[@backingInt(kind)] = .{ .bytes = created };
                },
                .fund => prep.funded += 1,
                .mint => prep.minted += 1,
            }
        }
        assert(prep.confirmed <= prep.sent);
    }

    fn remember(prep: *Prep, id: u64, item: Item) void {
        assert(id > 0);
        for (&prep.pending) |*entry| {
            if (entry.id != 0) continue;
            entry.* = .{ .id = id, .item = item };
            return;
        }
        unreachable; // At most `in_flight_limit` sends are pending in the driver.
    }

    fn forget(prep: *Prep, id: u64) Pending {
        assert(id > 0);
        for (&prep.pending) |*entry| {
            if (entry.id != id) continue;
            const pending = entry.*;
            entry.* = .{};
            return pending;
        }
        unreachable; // Every completion was remembered when it was sent.
    }

    /// Checks that each deployed address holds exactly the expected runtime code (a
    /// creation that ran out of gas still confirms, with status 0 and no code).
    fn verify(prep: *Prep, client: *rpc.Client) void {
        assert(prep.phase == .verify);
        for (contract_kinds, prep.deployed) |kind, address| {
            const matches = code_matches(client, address.?, kind) catch {
                prep.rpc_errors += 1;
                return; // Retried on the next step.
            };
            if (!matches) {
                prep.phase = .failed;
                return;
            }
        }
        prep.verified = true;
        prep.enter(.fund);
    }
};

fn code_matches(client: *rpc.Client, address: Address, kind: contracts.Kind) !bool {
    var params_buffer: [80]u8 = undefined;
    const params = std.fmt.bufPrint(&params_buffer, "[\"0x{x}\",\"latest\"]", .{
        &address.bytes,
    }) catch unreachable; // Fixed-size content.
    const value = try client.call("eth_getCode", params);
    var code_buffer: [runtime_bytes_max]u8 = undefined;
    const code = try rpc.data(value, &code_buffer);
    const expected = contracts.runtime_of(kind);
    assert(expected.len <= runtime_bytes_max);
    return std.mem.eql(u8, code, expected);
}

fn word(value: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value, .big);
    return out;
}

fn address_int(address: Address) u256 {
    return std.mem.readInt(u160, &address.bytes, .big);
}
