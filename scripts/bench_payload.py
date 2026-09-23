#!/usr/bin/env python3
"""Run Pilot on complete payloads; preserve raw output and unsupported cells."""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import re
import subprocess

METHODS = ['shamir', 'blakley', 'kothari', 'karchmer_wigderson', 'brickell',
           'massey', 'ramp', 'yamamoto', 'blakley_meadows', 'kgh', 'vss',
           'mignotte', 'asmuth_bloom', 'trivial', 'trivial_xor', 'ito',
           'benaloh_leichter', 'bytes', 'ida', 'visual', 'cgma_vss']
ROOT = Path(__file__).resolve().parents[1]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pilot', type=Path, default=Path.home()/'pilot-bench/build/cli/bench')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--cpp', type=Path, default=ROOT/'cpp/build/pilot_payload_cpp')
    ap.add_argument('--cpu', type=int, default=4)
    ap.add_argument('--preset', default='normal', choices=['quick', 'normal', 'strict'])
    ap.add_argument('--limit', type=int, default=180)
    args = ap.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    def command(cmd):
        p = subprocess.run(cmd, capture_output=True, text=True)
        return {'command': cmd, 'exit': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    metadata = {
        'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'host': platform.node(), 'platform': platform.platform(), 'cpu_affinity': args.cpu,
        'preset': args.preset, 'target_sample_ms': 20,
        'pilot_commit': command(['git', '-C', str(args.pilot.resolve().parents[2]), 'rev-parse', 'HEAD']),
        'source': command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']),
        'rump': command(['git', '-C', str(ROOT.parent/'rump'), 'rev-parse', 'HEAD']),
        'rust': command(['rustc', '--version']), 'cpp': command(['g++', '--version']),
        'cpu': command(['lscpu']), 'load': command(['uptime']),
        'pilot': command([str(args.pilot), '--version']),
    }
    (output/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    records = []
    def save():
        temp = output/'results.tmp'
        temp.write_text(json.dumps(records, indent=2)+'\n')
        temp.replace(output/'results.json')
    env = {**os.environ, 'PILOT_PAYLOAD_MS': '20'}
    for method in METHODS:
        for size in [64, 1024]:
            for phase in ['split', 'reconstruct']:
                implementations = ['rust', 'cpp'] if (size == 64) == (phase == 'split') else ['cpp', 'rust']
                for implementation in implementations:
                    row = {'method': method, 'bytes': size, 'phase': phase, 'implementation': implementation}
                    if implementation == 'cpp' and method != 'shamir':
                        records.append({**row, 'status': 'not_implemented'})
                        save()
                        continue
                    label = f'{method}-{size}-{phase}-{implementation}'
                    binary = ROOT/'target/release/pilot_payload' if implementation == 'rust' else args.cpp.resolve()
                    cmd = ['taskset', '-c', str(args.cpu), str(args.pilot), 'run_program',
                           '--preset', args.preset, '--session-limit', str(args.limit),
                           '--pi', f'{label},ms/payload,0,0,1', '--output-dir', str(output/label),
                           '--', str(binary), method, phase, str(size)]
                    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    print('RUN', label, flush=True)
                    try:
                        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=args.limit+120)
                        log = p.stdout+'\n'+p.stderr
                        (output/(label+'.log')).write_text(log)
                        def reading(pattern):
                            hits = re.findall(pattern, log)
                            return float(hits[-1]) if hits else None
                        mean = reading(r'Reading mean[^\n]*?([0-9]+(?:\.[0-9]*)?(?:[eE][+-]?[0-9]+)?)\s*(?:ms|$)')
                        ci = reading(r'Reading CI[^\n]*?([0-9]+(?:\.[0-9]*)?(?:[eE][+-]?[0-9]+)?)\s*(?:ms|$)')
                        rounds = reading(r'(?m)^Rounds:\s*(\d+)')
                        row.update(status='ok' if p.returncode == 0 and mean is not None and ci is not None else 'failed',
                                   exit=p.returncode, mean_ms=mean, ci_full_width_ms=ci, rounds=rounds)
                    except subprocess.TimeoutExpired as error:
                        row.update(status='timeout', error=str(error))
                    row.update(command=cmd, started_utc=started)
                    records.append(row)
                    save()
                    print('DONE', label, row['status'], row.get('mean_ms'), flush=True)
    metadata['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')

if __name__ == '__main__':
    main()
