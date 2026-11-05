//! Built-in chain configurations: Base mainnet, Base Sepolia, Base Zeronet and the local
//! devnet (L2), plus the Ethereum L1 fork schedules they settle on.
//! Mirrors base/base `crates/common/chains` (`ChainConfig`, `ethereum/*`).
//!
//! This is the canonical per-chain data. Consumers derive their own views from it:
//! the consensus lane's `RollupConfig`, the node lane's `ChainSpec`.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const Address = primitives.Address;
const B256 = primitives.B256;

/// Raw bootnode strings split by stack layer (separate discv5 networks).
pub const Bootnodes = struct {
    execution: []const []const u8 = &.{},
    consensus: []const []const u8 = &.{},
};

/// Base upgrade activation timestamps. OP Stack upgrades through Jovian are always
/// scheduled; later ones and the Pectra blob schedule are optional.
pub const Upgrades = struct {
    regolith: u64,
    canyon: u64,
    delta: u64,
    ecotone: u64,
    fjord: u64,
    granite: u64,
    holocene: u64,
    pectra_blob_schedule: ?u64 = null,
    isthmus: u64,
    jovian: u64,
    azul: ?u64 = null,
    beryl: ?u64 = null,
    cobalt: ?u64 = null,
    denim: ?u64 = null,
    everest: ?u64 = null,

    /// Every upgrade at `timestamp` (Azul included), later Base upgrades off.
    pub fn all_at(timestamp: u64) Upgrades {
        return .{
            .regolith = timestamp,
            .canyon = timestamp,
            .delta = timestamp,
            .ecotone = timestamp,
            .fjord = timestamp,
            .granite = timestamp,
            .holocene = timestamp,
            .isthmus = timestamp,
            .jovian = timestamp,
            .azul = timestamp,
        };
    }

    /// Scheduled upgrades never activate before an earlier one.
    pub fn is_ordered(upgrades: Upgrades) bool {
        var previous: u64 = 0;
        inline for (@typeInfo(Upgrades).@"struct".field_names) |name| {
            const value: ?u64 = @field(upgrades, name);
            if (value) |timestamp| {
                if (timestamp < previous) return false;
                previous = timestamp;
            }
        }
        return true;
    }
};

pub const ChainConfig = struct {
    /// Canonical namespaced name (`base`, `base-sepolia`, ...).
    name: []const u8,
    /// Base-centric operator selector (`mainnet`, `sepolia`, `zeronet`, `dev`).
    selector: []const u8,
    chain_id: u64,
    l1_chain_id: u64,

    block_time: u64 = 2,
    seq_window_size: u64 = 3600,
    max_sequencer_drift: u64 = 600,
    channel_timeout: u64 = 300,

    bedrock_block: u64 = 0,
    upgrades: Upgrades,

    genesis_l1_hash: B256 = .zero,
    genesis_l1_number: u64 = 0,
    genesis_l2_hash: B256 = .zero,
    genesis_l2_number: u64 = 0,
    genesis_l2_time: u64 = 0,
    genesis_batcher_address: Address = .zero,
    genesis_overhead: u256 = 0,
    genesis_scalar: u256 = 0,
    genesis_gas_limit: u64,

    eip1559_elasticity: u64 = 6,
    eip1559_denominator: u64 = 50,
    eip1559_denominator_canyon: u64 = 250,

    batch_inbox_address: Address = .zero,
    deposit_contract_address: Address = .zero,
    system_config_address: Address = .zero,
    protocol_versions_address: Address = .zero,

    unsafe_block_signer: ?Address = null,
    /// Admin seeded into the activation registry by Beryl (and Cobalt).
    beryl_activation_admin: ?Address = null,
    prune_delete_limit: u32 = 20_000,
    bootnodes: Bootnodes = .{},

    pub fn validate(config: *const ChainConfig) void {
        assert(config.chain_id != 0);
        assert(config.block_time > 0);
        assert(config.eip1559_denominator > 0 and config.eip1559_denominator_canyon > 0);
        assert(config.eip1559_elasticity > 0);
        assert(config.upgrades.is_ordered());
    }
};

fn address(comptime text: []const u8) Address {
    return Address.comptime_hex(text);
}

fn hash(comptime text: []const u8) B256 {
    return B256.comptime_hex(text);
}

pub const mainnet: ChainConfig = .{
    .name = "base",
    .selector = "mainnet",
    .chain_id = 8453,
    .l1_chain_id = 1,
    .upgrades = .{
        .regolith = 1_686_789_347,
        .canyon = 1_704_992_401,
        .delta = 1_708_560_000,
        .ecotone = 1_710_374_401,
        .fjord = 1_720_627_201,
        .granite = 1_726_070_401,
        .holocene = 1_736_445_601,
        .isthmus = 1_746_806_401,
        .jovian = 1_764_691_201,
        .azul = 1_779_991_200,
        .beryl = 1_782_410_400,
        .cobalt = 1_790_791_200,
        .denim = 1_793_901_600,
    },
    .genesis_l1_hash = hash("5c13d307623a926cd31415036c8b7fa14572f9dac64528e857a470511fc30771"),
    .genesis_l1_number = 17_481_768,
    .genesis_l2_hash = hash("f712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd"),
    .genesis_l2_time = 1_686_789_347,
    .genesis_batcher_address = address("5050f69a9786f081509234f1a7f4684b5e5b76c9"),
    .genesis_overhead = 0xbc,
    .genesis_scalar = 0xa6fe0,
    .genesis_gas_limit = 30_000_000,
    .batch_inbox_address = address("ff00000000000000000000000000000000008453"),
    .deposit_contract_address = address("49048044d57e1c92a77f79988d21fa8faf74e97e"),
    .system_config_address = address("73a79fab69143498ed3712e519a88a918e1f4072"),
    .protocol_versions_address = address("8062abc286f5e7d9428a0ccb9abd71e50d93b935"),
    .unsafe_block_signer = address("Af6E19BE0F9cE7f8afd49a1824851023A8249e8a"),
    .beryl_activation_admin = address("cE3a3bEE7E72E2A24079f3c0Cb3b97740ED425A9"),
    .prune_delete_limit = 20_000,
    .bootnodes = .{
        .execution = &.{
            "enode://87a32fd13bd596b2ffca97020e31aef4ddcc1bbd4b95bb633d16c1329f654f34049e" ++
                "d240a36b449fda5e5225d70fe40bc667f53c304b71f8e68fc9d448690b51@3.231.138.188:3" ++
                "0301",
            "enode://87a32fd13bd596b2ffca97020e31aef4ddcc1bbd4b95bb633d16c1329f654f34049e" ++
                "d240a36b449fda5e5225d70fe40bc667f53c304b71f8e68fc9d448690b51@3.231.138.188:9" ++
                "200",
            "enode://ca21ea8f176adb2e229ce2d700830c844af0ea941a1d8152a9513b966fe525e809c3" ++
                "a6c73a2c18a12b74ed6ec4380edf91662778fe0b79f6a591236e49e176f9@184.72.129.189:" ++
                "30301",
            "enode://ca21ea8f176adb2e229ce2d700830c844af0ea941a1d8152a9513b966fe525e809c3" ++
                "a6c73a2c18a12b74ed6ec4380edf91662778fe0b79f6a591236e49e176f9@184.72.129.189:" ++
                "9200",
            "enode://acf4507a211ba7c1e52cdf4eef62cdc3c32e7c9c47998954f7ba024026f9a6b2150c" ++
                "d3f0b734d9c78e507ab70d59ba61dfe5c45e1078c7ad0775fb251d7735a2@3.220.145.177:3" ++
                "0301",
            "enode://acf4507a211ba7c1e52cdf4eef62cdc3c32e7c9c47998954f7ba024026f9a6b2150c" ++
                "d3f0b734d9c78e507ab70d59ba61dfe5c45e1078c7ad0775fb251d7735a2@3.220.145.177:9" ++
                "200",
            "enode://8a5a5006159bf079d06a04e5eceab2a1ce6e0f721875b2a9c96905336219dbe14203" ++
                "d38f70f3754686a6324f786c2f9852d8c0dd3adac2d080f4db35efc678c5@3.231.11.52:303" ++
                "01",
            "enode://8a5a5006159bf079d06a04e5eceab2a1ce6e0f721875b2a9c96905336219dbe14203" ++
                "d38f70f3754686a6324f786c2f9852d8c0dd3adac2d080f4db35efc678c5@3.231.11.52:920" ++
                "0",
            "enode://cdadbe835308ad3557f9a1de8db411da1a260a98f8421d62da90e71da66e55e98aaa" ++
                "8e90aa7ce01b408a54e4bd2253d701218081ded3dbe5efbbc7b41d7cef79@54.198.153.150:" ++
                "30301",
            "enode://cdadbe835308ad3557f9a1de8db411da1a260a98f8421d62da90e71da66e55e98aaa" ++
                "8e90aa7ce01b408a54e4bd2253d701218081ded3dbe5efbbc7b41d7cef79@54.198.153.150:" ++
                "9200",
        },
        .consensus = &.{
            "enr:-J24QNz9lbrKbN4iSmmjtnr7SjUMk4zB7f1krHZcTZx-JRKZd0kA2gjufUROD6T3sOWDVDnF" ++
                "JRvqBBo62zuF-hYCohOGAYiOoEyEgmlkgnY0gmlwhAPniryHb3BzdGFja4OFQgCJc2VjcDI1Nmsx" ++
                "oQKNVFlCxh_B-716tTs-h1vMzZkSs1FTu_OYTNjgufplG4N0Y3CCJAaDdWRwgiQG",
            "enr:-J24QH-f1wt99sfpHy4c0QJM-NfmsIfmlLAMMcgZCUEgKG_BBYFc6FwYgaMJMQN5dsRBJApI" ++
                "ok0jFn-9CS842lGpLmqGAYiOoDRAgmlkgnY0gmlwhLhIgb2Hb3BzdGFja4OFQgCJc2VjcDI1Nmsx" ++
                "oQJ9FTIv8B9myn1MWaC_2lJ-sMoeCDkusCsk4BYHjjCq04N0Y3CCJAaDdWRwgiQG",
            "enr:-J24QDXyyxvQYsd0yfsN0cRr1lZ1N11zGTplMNlW4xNEc7LkPXh0NAJ9iSOVdRO95GPYAIc6" ++
                "xmyoCCG6_0JxdL3a0zaGAYiOoAjFgmlkgnY0gmlwhAPckbGHb3BzdGFja4OFQgCJc2VjcDI1Nmsx" ++
                "oQJwoS7tzwxqXSyFL7g0JM-KWVbgvjfB8JA__T7yY_cYboN0Y3CCJAaDdWRwgiQG",
            "enr:-J24QHmGyBwUZXIcsGYMaUqGGSl4CFdx9Tozu-vQCn5bHIQbR7On7dZbU61vYvfrJr30t0ia" ++
                "hSqhc64J46MnUO2JvQaGAYiOoCKKgmlkgnY0gmlwhAPnCzSHb3BzdGFja4OFQgCJc2VjcDI1Nmsx" ++
                "oQINc4fSijfbNIiGhcgvwjsjxVFJHUstK9L1T8OTKUjgloN0Y3CCJAaDdWRwgiQG",
            "enr:-J24QG3ypT4xSu0gjb5PABCmVxZqBjVw9ca7pvsI8jl4KATYAnxBmfkaIuEqy9sKvDHKuNCs" ++
                "y57WwK9wTt2aQgcaDDyGAYiOoGAXgmlkgnY0gmlwhDbGmZaHb3BzdGFja4OFQgCJc2VjcDI1Nmsx" ++
                "oQIeAK_--tcLEiu7HvoUlbV52MspE0uCocsx1f_rYvRenIN0Y3CCJAaDdWRwgiQG",
        },
    },
};

pub const sepolia: ChainConfig = .{
    .name = "base-sepolia",
    .selector = "sepolia",
    .chain_id = 84532,
    .l1_chain_id = 11_155_111,
    .upgrades = .{
        .regolith = 1_695_768_288,
        .canyon = 1_699_981_200,
        .delta = 1_703_203_200,
        .ecotone = 1_708_534_800,
        .fjord = 1_716_998_400,
        .granite = 1_723_478_400,
        .holocene = 1_732_633_200,
        .pectra_blob_schedule = 1_742_486_400,
        .isthmus = 1_744_905_600,
        .jovian = 1_763_568_001,
        .azul = 1_776_708_000,
        .beryl = 1_781_805_600,
        .cobalt = 1_790_186_400,
        .denim = 1_792_605_600,
    },
    .genesis_l1_hash = hash("cac9a83291d4dec146d6f7f69ab2304f23f5be87b1789119a0c5b1e4482444ed"),
    .genesis_l1_number = 4_370_868,
    .genesis_l2_hash = hash("0dcc9e089e30b90ddfc55be9a37dd15bc551aeee999d2e2b51414c54eaf934e4"),
    .genesis_l2_time = 1_695_768_288,
    .genesis_batcher_address = address("6cdebe940bc0f26850285caca097c11c33103e47"),
    .genesis_overhead = 0x834,
    .genesis_scalar = 0xf4240,
    .genesis_gas_limit = 25_000_000,
    .eip1559_elasticity = 10,
    .batch_inbox_address = address("ff00000000000000000000000000000000084532"),
    .deposit_contract_address = address("49f53e41452c74589e85ca1677426ba426459e85"),
    .system_config_address = address("f272670eb55e895584501d564afeb048bed26194"),
    .protocol_versions_address = address("79add5713b383daa0a138d3c4780c7a1804a8090"),
    .unsafe_block_signer = address("b830b99c95Ea32300039624Cb567d324D4b1D83C"),
    .beryl_activation_admin = address("5F43072722f59964d886CBb507F6a85ca0759D42"),
    .prune_delete_limit = 10_000,
    .bootnodes = .{
        .execution = &.{
            "enode://548f715f3fc388a7c917ba644a2f16270f1ede48a5d88a4d14ea287cc916068363f3" ++
                "092e39936f1a3e7885198bef0e5af951f1d7b1041ce8ba4010917777e71f@18.210.176.114:" ++
                "30301",
            "enode://548f715f3fc388a7c917ba644a2f16270f1ede48a5d88a4d14ea287cc916068363f3" ++
                "092e39936f1a3e7885198bef0e5af951f1d7b1041ce8ba4010917777e71f@18.210.176.114:" ++
                "9200",
            "enode://6f10052847a966a725c9f4adf6716f9141155b99a0fb487fea3f51498f4c2a2cb8d5" ++
                "34e680ee678f9447db85b93ff7c74562762c3714783a7233ac448603b25f@107.21.251.55:3" ++
                "0301",
            "enode://6f10052847a966a725c9f4adf6716f9141155b99a0fb487fea3f51498f4c2a2cb8d5" ++
                "34e680ee678f9447db85b93ff7c74562762c3714783a7233ac448603b25f@107.21.251.55:9" ++
                "200",
        },
        .consensus = &.{
            "enr:-J64QFa3qMsONLGphfjEkeYyF6Jkil_jCuJmm7_a42ckZeUQGLVzrzstZNb1dgBp1GGx9bzI" ++
                "mq5VxJLP-BaptZThGiWGAYrTytOvgmlkgnY0gmlwhGsV-zeHb3BzdGFja4S0lAUAiXNlY3AyNTZr" ++
                "MaEDahfSECTIS_cXyZ8IyNf4leANlZnrsMEWTkEYxf4GMCmDdGNwgiQGg3VkcIIkBg",
            "enr:-J64QBwRIWAco7lv6jImSOjPU_W266lHXzpAS5YOh7WmgTyBZkgLgOwo_mxKJq3wz2XRbsoB" ++
                "Itbv1dCyjIoNq67mFguGAYrTxM42gmlkgnY0gmlwhBLSsHKHb3BzdGFja4S0lAUAiXNlY3AyNTZr" ++
                "MaEDmoWSi8hcsRpQf2eJsNUx-sqv6fH4btmo2HsAzZFAKnKDdGNwgiQGg3VkcIIkBg",
        },
    },
};

pub const zeronet: ChainConfig = .{
    .name = "base-zeronet",
    .selector = "zeronet",
    .chain_id = 763_360,
    .l1_chain_id = 560_048,
    .upgrades = upgrades: {
        var upgrades = Upgrades.all_at(1_782_348_588);
        upgrades.azul = 1_782_348_888;
        upgrades.beryl = 1_782_349_188;
        break :upgrades upgrades;
    },
    .genesis_l1_hash = hash("acb2c60e3887888b5111b05c8d8f32e2761c7d4a0f10562d199253ab072c3a71"),
    .genesis_l1_number = 3_083_762,
    .genesis_l2_hash = hash("572a15dd7e69df35913f7f2217376609fc20d59276169977de92c01684637162"),
    .genesis_l2_time = 1_782_348_588,
    .genesis_batcher_address = address("4c810fec547f6c143db51953af51a1de79bead21"),
    .genesis_scalar = 0x010000000000000000000000000000000000000000000000000c3c9d00000558,
    .genesis_gas_limit = 25_000_000,
    .batch_inbox_address = address("00975f9c430b216f84ec52374d7f5eb8eec3139a"),
    .deposit_contract_address = address("7e3b97c95c823f385ff6770411f6e12f8e09ac9b"),
    .system_config_address = address("0a111c7980152bde41d71f48e2e1d8184f5f6187"),
    .protocol_versions_address = address("646c8604cf62b23e0cf094f2e790c6c75547ff85"),
    .unsafe_block_signer = address("cf17274338d3128f6C96d9af54511a17e8b38a08"),
    .beryl_activation_admin = address("F5969A85a555671EeD766C4ff0C61426AA626b11"),
    .prune_delete_limit = 10_000,
    .bootnodes = .{
        .execution = &.{
            "enode://695c5367f2934114e567a3b4ea77a629ff1c9fdfa0290afbe4c79de9ebd8e1448763" ++
                "c4fc4ce203f5e4bce05f293b756e190ae73609bff858377d79fc7905b0d8@54.90.107.224:3" ++
                "0301",
            "enode://695c5367f2934114e567a3b4ea77a629ff1c9fdfa0290afbe4c79de9ebd8e1448763" ++
                "c4fc4ce203f5e4bce05f293b756e190ae73609bff858377d79fc7905b0d8@54.90.107.224:9" ++
                "200",
        },
        .consensus = &.{
            "enr:-Ji4QLr5n2VbXQohRywhyi2_efPpMcKzKL7DtllVNgkn_fDuGszrobGsTjM9WX7TxVqbW6YX" ++
                "8pxEx7lmvHprVc3HX8wBgmlkgnY0gmlwhDZaa-CHb3BzdGFja4Tgyy4AiXNlY3AyNTZrMaEDG1Gm" ++
                "DUlW2vWzc7QQ_QOgPFG1Gfn-sCC8FQTef-GdCo2DdGNwgiQGg3VkcIIkBg",
        },
    },
};

/// Local devnet: every upgrade through Azul active at genesis.
pub const devnet: ChainConfig = .{
    .name = "dev",
    .selector = "dev",
    .chain_id = 84_538_453,
    .l1_chain_id = 1337,
    .upgrades = Upgrades.all_at(0),
    .genesis_gas_limit = 30_000_000,
    .beryl_activation_admin = address("9965507D1a55bcC2695C58ba16FB37d819B0A4dc"),
};

pub const all = [_]*const ChainConfig{ &mainnet, &sepolia, &devnet, &zeronet };

/// Namespaced canonical names (`base`, `base-sepolia`, `base_sepolia`, `base-zeronet`, `dev`).
pub fn by_name(name: []const u8) ?*const ChainConfig {
    if (std.mem.eql(u8, name, "base_sepolia")) return &sepolia;
    for (all) |config| {
        if (std.mem.eql(u8, config.name, name)) return config;
    }
    return null;
}

/// Base-centric selectors (`mainnet` means Base mainnet, not Ethereum mainnet).
pub fn from_base_chain(selector: []const u8) ?*const ChainConfig {
    for (all) |config| {
        if (std.mem.eql(u8, config.selector, selector)) return config;
    }
    return null;
}

/// Either naming surface; chain parsers should use this.
pub fn by_any_name(name: []const u8) ?*const ChainConfig {
    return from_base_chain(name) orelse by_name(name);
}

pub fn by_chain_id(chain_id: u64) ?*const ChainConfig {
    for (all) |config| {
        if (config.chain_id == chain_id) return config;
    }
    return null;
}

/// Post-merge Ethereum L1 fork schedule (timestamps; null means unscheduled).
pub const L1Config = struct {
    chain_id: u64,
    shanghai: ?u64,
    cancun: ?u64,
    prague: ?u64,
    osaka: ?u64,
    bpo1: ?u64,
    bpo2: ?u64,
    deposit_contract_address: ?Address = null,
};

pub const l1_mainnet: L1Config = .{
    .chain_id = 1,
    .shanghai = 1_681_338_455,
    .cancun = 1_710_338_135,
    .prague = 1_746_612_311,
    .osaka = 1_764_798_551,
    .bpo1 = 1_765_290_071,
    .bpo2 = 1_767_747_671,
    .deposit_contract_address = address("00000000219ab540356cbb839cbe05303d7705fa"),
};

pub const l1_sepolia: L1Config = .{
    .chain_id = 11_155_111,
    .shanghai = 1_677_557_088,
    .cancun = 1_706_655_072,
    .prague = 1_741_159_776,
    .osaka = 1_760_427_360,
    .bpo1 = 1_761_017_184,
    .bpo2 = 1_761_607_008,
    .deposit_contract_address = address("7f02c3e3c98b133055b8b348b2ac625669ed295d"),
};

pub const l1_holesky: L1Config = .{
    .chain_id = 17000,
    .shanghai = 1_696_000_704,
    .cancun = 1_707_305_664,
    .prague = 1_740_434_112,
    .osaka = 1_759_308_480,
    .bpo1 = 1_759_800_000,
    .bpo2 = 1_760_389_824,
    .deposit_contract_address = address("4242424242424242424242424242424242424242"),
};

pub const l1_hoodi: L1Config = .{
    .chain_id = 560_048,
    .shanghai = 0,
    .cancun = 0,
    .prague = 1_742_999_832,
    .osaka = 1_761_677_592,
    .bpo1 = 1_762_365_720,
    .bpo2 = 1_762_955_544,
    .deposit_contract_address = address("00000000219ab540356cbb839cbe05303d7705fa"),
};

/// Local devnet L1: everything through BPO2 at genesis.
pub const l1_devnet: L1Config = .{
    .chain_id = 1337,
    .shanghai = 0,
    .cancun = 0,
    .prague = 0,
    .osaka = 0,
    .bpo1 = 0,
    .bpo2 = 0,
};

pub fn l1_by_chain_id(chain_id: u64) ?*const L1Config {
    const configs = [_]*const L1Config{
        &l1_mainnet, &l1_sepolia, &l1_holesky, &l1_hoodi, &l1_devnet,
    };
    for (configs) |config| {
        if (config.chain_id == chain_id) return config;
    }
    return null;
}

const testing = std.testing;

test "chains: every config validates and its L1 is known" {
    for (all) |config| {
        config.validate();
        try testing.expect(l1_by_chain_id(config.l1_chain_id) != null);
        try testing.expectEqual(config, by_chain_id(config.chain_id).?);
        try testing.expectEqual(config, from_base_chain(config.selector).?);
        try testing.expectEqual(config, by_any_name(config.name).?);
    }
}

test "chains: naming surfaces stay distinct" {
    try testing.expectEqual(&sepolia, by_name("base_sepolia").?);
    try testing.expect(by_name("mainnet") == null);
    try testing.expect(from_base_chain("base") == null);
    try testing.expect(by_any_name("not-a-chain") == null);
}

test "chains: genesis-active upgrades use the genesis timestamp" {
    try testing.expectEqual(mainnet.genesis_l2_time, mainnet.upgrades.regolith);
    try testing.expectEqual(sepolia.genesis_l2_time, sepolia.upgrades.regolith);
    try testing.expectEqual(zeronet.genesis_l2_time, zeronet.upgrades.jovian);
    try testing.expectEqual(@as(?u64, 1_782_349_188), zeronet.upgrades.beryl);
    try testing.expect(zeronet.upgrades.cobalt == null);
    var broken = mainnet.upgrades;
    broken.canyon = 0;
    try testing.expect(!broken.is_ordered());
}

test "chains: bootnodes are well formed" {
    for (all) |config| {
        for (config.bootnodes.execution) |node| {
            try testing.expect(std.mem.startsWith(u8, node, "enode://"));
        }
        for (config.bootnodes.consensus) |node| {
            try testing.expect(std.mem.startsWith(u8, node, "enr:"));
        }
    }
    try testing.expectEqual(@as(usize, 10), mainnet.bootnodes.execution.len);
}
