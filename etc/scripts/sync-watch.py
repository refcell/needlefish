"""Watch a needlefish node follow the chain tip and check it against a reference node.

usage: python3 -I etc/scripts/sync-watch.py [--el URL] [--cl URL] [--reference URL]
           [--log PATH] [--duration S] [--snapshot N]

Read-only: it only sends JSON-RPC reads. Every block the node's execution client (`base
el-run --rpc`, --el) commits is printed on one line with the reference's hash for the same
number: equal hashes mean the node executed the same chain, block for block. With --log
(el-run's log file) each line also shows el-run's execution time, tip lag, and its own
checks (transactions, gas, bloom, receipts, state and withdrawals roots, resealed hash).
Every 5 s the consensus node's (`base consensus`, --cl) safe and finalized heads are compared
by number and hash with the reference's blocks at the same numbers. --duration stops after S seconds with a
summary; Ctrl-C prints it too. Exit 0 when every comparison matched, 1 otherwise.
"""
import argparse, json, os, re, sys, time, urllib.parse, urllib.request

GREEN, RED, DIM, BOLD, RESET = '\033[32m', '\033[31m', '\033[2m', '\033[1m', '\033[0m'
OK, BAD = GREEN + '✓' + RESET, RED + '✗' + RESET
BLOCKS_PER_POLL_MAX = 64
HEADS_EVERY_S = 5.0
LOG_WAIT_S = 2.0
LOG_LINE = re.compile(r'^block (\d+) hash \S+ (\d+) txs (\d+) gas (\d+) ms lag_ms (\d+) (.*)$')


def rpc(url, calls):
    body = json.dumps([{'jsonrpc': '2.0', 'id': i, 'method': m, 'params': p}
                       for i, (m, p) in enumerate(calls)]).encode()
    request = urllib.request.Request(url, body, {'Content-Type': 'application/json',
                                                 'User-Agent': 'needlefish-sync-watch'})
    with urllib.request.urlopen(request, timeout=10) as response:
        answers = json.load(response)
    if isinstance(answers, dict):
        raise RuntimeError(f'{url}: {answers.get("error")}')
    by_id = {a['id']: a for a in answers}
    errors = [a['error'] for a in answers if 'error' in a]
    if errors:  # mainnet.base.org rate limits each batch item (25/s): retried next poll
        raise RuntimeError(f'{url}: {errors[0]}')
    return [by_id[i].get('result') for i in range(len(calls))]


def blocks(url, numbers):
    return rpc(url, [('eth_getBlockByNumber', [hex(n), False]) for n in numbers])


def short(hash_hex):
    return hash_hex[:10] + '…' + hash_hex[-8:]


class LogTail:
    """New `block N ...` lines of el-run's log, from the end of the file at start."""

    def __init__(self, path):
        self.file = open(path, 'rb') if path else None
        if self.file:
            self.file.seek(0, os.SEEK_END)
        self.rest = b''
        self.lines = {}

    def poll(self):
        if not self.file:
            return
        data = self.rest + self.file.read()
        *complete, self.rest = data.split(b'\n')
        for raw in complete:
            match = LOG_LINE.match(raw.decode(errors='replace'))
            if match:
                number, txs, gas, ms, lag, checks = match.groups()
                self.lines[int(number)] = (int(ms), int(lag), checks)


class Watch:
    def __init__(self, args, head):
        self.args = args
        self.log = LogTail(args.log)
        self.pending = []  # (number, local block, first seen)
        self.next = head + 1  # from the next commit on: its log line is still to come
        self.matched = self.mismatched = self.checks_ok = self.checks_bad = 0
        self.heads_matched = self.heads_mismatched = 0
        self.lags = []
        self.last_heads = 0.0
        self.host = urllib.parse.urlparse(args.reference).hostname

    def poll_blocks(self):
        head = int(rpc(self.args.el, [('eth_blockNumber', [])])[0], 16)
        first = max(self.next, head - BLOCKS_PER_POLL_MAX + 1)
        numbers = list(range(first, head + 1))
        now = time.monotonic()
        for number, block in zip(numbers, blocks(self.args.el, numbers) if numbers else []):
            if block:
                self.pending.append((number, block, now))
        self.next = head + 1
        self.log.poll()
        ready = 0  # a prefix of pending, so lines stay in block order
        for number, _, seen in self.pending:
            if self.log.file and number not in self.log.lines and now - seen < LOG_WAIT_S:
                break
            ready += 1
        if not ready:
            return
        reference = blocks(self.args.reference, [p[0] for p in self.pending[:ready]])
        for (number, block, _), theirs in zip(self.pending[:ready], reference):
            if theirs is None:
                break  # the reference has not seen it yet: next poll
            self.pending.pop(0)
            self.print_block(number, block, theirs)

    def print_block(self, number, block, theirs):
        same = block['hash'] == theirs['hash']
        self.matched += same
        self.mismatched += not same
        execution = ''
        if number in self.log.lines:
            ms, lag, checks = self.log.lines.pop(number)
            ok = checks == 'checks ok'
            self.checks_ok += ok
            self.checks_bad += not ok
            self.lags.append(lag)
            execution = f'{ms:>3} ms  lag {lag:>4} ms  {checks} {OK if ok else BAD}  '
        txs = len(block['transactions'])
        mark = OK if same else BAD + f' it has {short(theirs["hash"])}'
        print(f'block {number}  {short(block["hash"])}  {txs:>3} txs  {execution}'
              f'{DIM}= {self.host}{RESET} {mark}', flush=True)

    def poll_heads(self):
        if not self.args.cl or time.monotonic() - self.last_heads < HEADS_EVERY_S:
            return
        self.last_heads = time.monotonic()
        status = rpc(self.args.cl, [('optimism_syncStatus', [])])[0]
        heads = [(label, status[key]) for label, key in
                 (('safe', 'safe_l2'), ('finalized', 'finalized_l2'))]
        theirs = blocks(self.args.reference, [head['number'] for _, head in heads])
        tags = blocks_by_tag(self.args.reference)
        for (label, head), block in zip(heads, theirs):
            same = block is not None and block['hash'] == head['hash']
            self.heads_matched += same
            self.heads_mismatched += not same
            tag = tags[label]
            note = f'{self.host}\'s {label} head too' if tag['hash'] == head['hash'] else \
                f'{self.host}\'s {label} head is {int(tag["number"], 16)}'
            print(f'{BOLD}{label:<9}{RESET} {head["number"]}  {short(head["hash"])}  '
                  f'{DIM}= {self.host}{RESET} {OK if same else BAD}  {DIM}({note}){RESET}',
                  flush=True)

    def summary(self):
        lags = sorted(self.lags)
        median = f', median tip lag {lags[len(lags) // 2]} ms' if lags else ''
        print(f'\n{BOLD}{self.matched + self.mismatched} blocks followed{RESET}: '
              f'{self.matched} hashes equal {self.host}\'s, {self.mismatched} differ' + median)
        if self.log.file:
            print(f'el-run checks: {self.checks_ok} ok, {self.checks_bad} failed')
        if self.args.cl:
            print(f'safe/finalized comparisons: {self.heads_matched} equal {self.host}\'s, '
                  f'{self.heads_mismatched} differ')
        return self.mismatched + self.checks_bad + self.heads_mismatched == 0


def blocks_by_tag(url):
    safe, finalized = rpc(url, [('eth_getBlockByNumber', ['safe', False]),
                                ('eth_getBlockByNumber', ['finalized', False])])
    return {'safe': safe, 'finalized': finalized}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--el', default='http://127.0.0.1:8546')
    parser.add_argument('--cl', default='http://127.0.0.1:7546', help="'' to skip")
    parser.add_argument('--reference', default='https://mainnet.base.org')
    parser.add_argument('--log', help="el-run's log file")
    parser.add_argument('--duration', type=float, default=0, help='seconds, 0 for no limit')
    parser.add_argument('--snapshot', type=int, help='block the node started from')
    parser.add_argument('--poll-ms', type=int, default=250)
    args = parser.parse_args()
    head = int(rpc(args.el, [('eth_blockNumber', [])])[0], 16)
    client = rpc(args.el, [('web3_clientVersion', [])])[0]
    print(f'{BOLD}{client}{RESET} at {args.el}, head {head}' +
          (f', {head - args.snapshot} blocks executed since the snapshot at {args.snapshot}'
           if args.snapshot else ''))
    print(f'{DIM}reference: {args.reference}{RESET}\n', flush=True)
    watch = Watch(args, head)
    started = time.monotonic()
    try:
        while not args.duration or time.monotonic() - started < args.duration:
            try:
                watch.poll_heads()
                watch.poll_blocks()
            except (OSError, RuntimeError, ValueError):
                time.sleep(1)  # a refused or failed read compares nothing: try again
            time.sleep(args.poll_ms / 1000)
    except KeyboardInterrupt:
        pass
    sys.exit(0 if watch.summary() else 1)


if __name__ == '__main__':
    main()
