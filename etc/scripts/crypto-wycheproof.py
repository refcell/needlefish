#!/usr/bin/env python3
"""Convert public Wycheproof vectors (C2SP/wycheproof, Apache-2.0) into the compact line
formats read by src/common/crypto/wycheproof_tests.zig.

Usage: etc/scripts/crypto-wycheproof.py <dir with the downloaded .json files>

ECDSA (P1363, SHA-256), per key group:  K <x||y hex>
  then per test:                          T <sha256(msg) hex> <r hex> <s hex> <1|0>
  Signatures that are not exactly 64 bytes cannot be expressed as (r, s) and are skipped.
ECDH secp256k1:                           E <private hex> <public sec1 hex> <shared x hex|-> <1|0>
  Only keys whose SPKI names secp256k1 and parses are kept (ASN.1 / wrong-curve cases do not
  apply to a raw-point API; InvalidAsn cases are dropped). 'acceptable' counts as valid.
"""
import hashlib, json, sys, os

def ecdsa(path, out):
    data = json.load(open(path))
    lines = [f"# {os.path.basename(path)} ({data['generatorVersion'] if 'generatorVersion' in data else ''})"]
    skipped = 0
    for group in data['testGroups']:
        key = group['publicKey']['uncompressed']
        assert key[:2] == '04'
        lines.append('K ' + key[2:])
        for test in group['tests']:
            sig = test['sig']
            if len(sig) != 128:
                skipped += 1
                continue
            digest = hashlib.sha256(bytes.fromhex(test['msg'])).hexdigest()
            valid = '1' if test['result'] == 'valid' else '0'
            assert test['result'] in ('valid', 'invalid')
            lines.append(f"T {digest} {sig[:64]} {sig[64:]} {valid}")
    open(out, 'w').write('\n'.join(lines) + '\n')
    print(out, len(lines), 'lines, skipped', skipped)

SECP256K1_SPKI_PREFIXES = (
    '3056301006072a8648ce3d020106052b8104000a034200',  # uncompressed point
    '3036301006072a8648ce3d020106052b8104000a032200',  # compressed point
)

def ecdh(path, out):
    data = json.load(open(path))
    lines = [f"# {os.path.basename(path)}"]
    kept = skipped = 0
    for group in data['testGroups']:
        for test in group['tests']:
            # ASN.1 malformations: parsers may accept them, but the point bytes can differ
            # from the key the expected secret was computed with.
            if 'InvalidAsn' in test['flags']:
                skipped += 1
                continue
            public = test['public']
            point = None
            for prefix in SECP256K1_SPKI_PREFIXES:
                if public.startswith(prefix):
                    point = public[len(prefix):]
            expected_len = {'04': 130, '02': 66, '03': 66}
            if point is None or len(point) != expected_len.get(point[:2], -1):
                skipped += 1
                continue
            private = int(test['private'], 16).to_bytes(32, 'big').hex()
            valid = test['result'] in ('valid', 'acceptable')
            shared = test['shared'] if valid else '-'
            lines.append(f"E {private} {point} {shared} {'1' if valid else '0'}")
            kept += 1
    open(out, 'w').write('\n'.join(lines) + '\n')
    print(out, 'kept', kept, 'skipped', skipped)

source = sys.argv[1]
target = 'src/common/crypto/vectors'
ecdsa(f'{source}/ecdsa_secp256k1_sha256_p1363_test.json', f'{target}/wycheproof_ecdsa_secp256k1.txt')
ecdsa(f'{source}/ecdsa_secp256r1_sha256_p1363_test.json', f'{target}/wycheproof_ecdsa_secp256r1.txt')
ecdh(f'{source}/ecdh_secp256k1_test.json', f'{target}/wycheproof_ecdh_secp256k1.txt')
