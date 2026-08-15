from probe import make_env, run_chain
import os
env = make_env()
fixdir = None
from aicomp_sdk.evaluation.ops import resolve_fixtures_dir
fx = resolve_fixtures_dir(None)
seed_dir = os.path.join(str(fx), "file_seed")
files = sorted(os.listdir(seed_dir))
print("testing", len(files), "files via 'read file <name>'")
for f in files:
    stem = f.rsplit(".",1)[0]
    preds, breach, tools = run_chain(env, [f"read file {stem}"])
    pnames = sorted({p['predicate'] for p in preds})
    seq = " -> ".join(f"{n}[{se}]{'' if ok else 'X'}" for (n,s,se,ok) in tools)
    flag = "  <<< BREACH" if breach else ("  * pred" if pnames else "")
    print(f"{f:28s} {pnames} {flag}")
    if pnames or breach:
        print("     ", seq)
