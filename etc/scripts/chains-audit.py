"""Cross-check src/common/chains/root.zig against base/base chains/src/config.rs.

usage: python3 etc/scripts/chains-audit.py <base-base-checkout>
"""
import re, sys
if len(sys.argv) != 2:
    sys.exit(__doc__)
rs = open(sys.argv[1] + '/crates/common/chains/src/config.rs').read()
zg=open('src/common/chains/root.zig').read()
def num(v):
    v=v.strip().replace('_','')
    m=re.match(r'uint!\((0x[0-9a-fA-F]+)U256\)',v)
    if m: return int(m.group(1),16)
    if v=='.zero': return 'ZERO'
    if v in('U256::ZERO',): return 0
    if v in('B256::ZERO','Address::ZERO'): return 'ZERO'
    m=re.match(r'(?:b256|address)!\("([0-9a-fA-F]+)"\)',v) or re.match(r'(?:hash|address)\("([0-9a-fA-F]+)"\)',v)
    if m: return 'ZERO' if re.fullmatch(r'0+',m.group(1)) else m.group(1).lower()
    if v.startswith('Some('): return num(v[5:-1])
    if v=='None': return None
    if re.match(r'^0x[0-9a-fA-F]+$',v): return int(v,16)
    if re.match(r'^\d+$',v): return int(v)
    return v
def strings(block):
    return re.findall(r'"((?:enode|enr)[^"]*)"', re.sub(r'"\s*\+\+\s*"','',block))
rust={}
for m in re.finditer(r'const (\w+): ChainConfig = ChainConfig \{(.*?)\n\};',rs,re.S):
    body=m.group(2); f={}
    for k,v in re.findall(r'^    (\w+): (.*?),$',body,re.M): f[k]=num(v)
    f['bootnodes']=strings(body)
    rust[m.group(1)]=f
# zig defaults
sd=zg[zg.index('pub const ChainConfig = struct {'):]
sd=sd[:sd.index('\n};')]
defaults={k:num(v) for k,v in re.findall(r'^    (\w+): [^=\n]+= (.*?),$',sd,re.M)}
defaults.update({k:None for k in ['pectra_blob_schedule','azul','beryl','cobalt','denim','everest','unsafe_block_signer']})
zig={}
for m in re.finditer(r'pub const (\w+): ChainConfig = \.\{(.*?)\n\};',zg,re.S):
    body=m.group(2); f=dict(defaults)
    a=re.search(r'all_at\(([\d_]+)\)',body)
    if a:
        for k in ['regolith','canyon','delta','ecotone','fjord','granite','holocene','isthmus','jovian','azul']: f[k]=num(a.group(1))
    for k,v in re.findall(r'upgrades\.(\w+) = ([\d_]+);',body): f[k]=num(v)
    for k,v in re.findall(r'^\s+\.(\w+) = (.*?),$',body,re.M): f[k]=num(v)
    f['bootnodes']=strings(body)
    zig[m.group(1)]=f
names={'MAINNET':'mainnet','SEPOLIA':'sepolia','DEVNET':'devnet','ZERONET':'zeronet'}
print('rust consts',list(rust),'zig consts',list(zig))
bad=0
for r,z in names.items():
    if r not in rust or z not in zig: print('missing',r,z); bad+=1; continue
    for k,v in rust[r].items():
        if k=='genesis_json': continue
        zk=k[:-len('_timestamp')] if k.endswith('_timestamp') else k
        zv=zig[z].get(zk,'<absent>')
        if zv!=v: print(r,k,'rust=',v,'zig=',zv); bad+=1
print('mismatches', bad)
sys.exit(1 if bad else 0)
