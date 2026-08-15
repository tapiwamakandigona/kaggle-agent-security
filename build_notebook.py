import json
src = open("submission/attack.py").read()

def code(s): return {"cell_type":"code","metadata":{},"execution_count":None,"outputs":[],
                     "source": s.splitlines(keepends=True)}
def md(s):   return {"cell_type":"markdown","metadata":{},"source": s.splitlines(keepends=True)}

intro = (
"# AI Agent Security — Multi-Step Tool Attacks\n"
"**Go-Explore search + taint-laundering seed library**\n\n"
"This notebook (1) adds the competition dataset root to `sys.path`, (2) writes our "
"`AttackAlgorithm` to `/kaggle/working/attack.py`, and (3) starts the competition "
"inference server, which discovers `attack.py`, replays candidates against the target "
"models under the guardrails, and writes `submission.csv`.\n\n"
"Method: exploit three verified guardrail blind spots — argument shadowing, the "
"5-event taint window, and the web/email-only source gap — and farm diverse breaching "
"cells with a Go-Explore archive seeded by a laundering-seed library. Full detail in "
"the Working Note.")

setup = (
"import sys, glob\n"
"from pathlib import Path\n"
"# Prevent argparse conflicts in Kaggle notebooks\n"
"sys.argv = [sys.argv[0]]\n"
"# The competition dataset contains kaggle_evaluation/ and aicomp_sdk/ at its root\n"
"for candidate in glob.glob('/kaggle/input/**/kaggle_evaluation', recursive=True):\n"
"    dataset_root = str(Path(candidate).parent)\n"
"    if dataset_root not in sys.path:\n"
"        sys.path.insert(0, dataset_root)\n"
"    print('Dataset root:', dataset_root)\n"
"    break\n"
"print('Setup complete')\n")

# write attack.py via a raw-string wrapper so the source is embedded verbatim
writecell = (
"attack_code = r'''\n" + src + "\n'''\n"
"with open('/kaggle/working/attack.py', 'w') as f:\n"
"    f.write(attack_code)\n"
"print('Wrote /kaggle/working/attack.py', len(attack_code), 'bytes')\n"
"# sanity: import it against the real SDK\n"
"import importlib.util\n"
"spec = importlib.util.spec_from_file_location('attack', '/kaggle/working/attack.py')\n"
"m = importlib.util.module_from_spec(spec); sys.modules['attack'] = m; spec.loader.exec_module(m)\n"
"from aicomp_sdk.attacks import AttackAlgorithmBase\n"
"assert issubclass(m.AttackAlgorithm, AttackAlgorithmBase)\n"
"print('attack.py OK: AttackAlgorithm valid subclass')\n")

serve = (
"# During the competition rerun the gateway is present: start the inference server,\n"
"# which loads /kaggle/working/attack.py, replays candidates against the target models\n"
"# under the guardrails, and writes the real submission.csv. During a normal commit\n"
"# (no gateway) we write a placeholder submission.csv so the submission validates.\n"
"import os, csv\n"
"if os.getenv('KAGGLE_IS_COMPETITION_RERUN'):\n"
"    import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as jed\n"
"    jed.JEDAttackInferenceServer().serve()\n"
"else:\n"
"    with open('/kaggle/working/submission.csv', 'w', newline='') as fh:\n"
"        w = csv.writer(fh)\n"
"        w.writerow(['Id', 'Score'])\n"
"        w.writerows([['gpt_oss_public', 0.0], ['gpt_oss_private', 0.0],\n"
"                     ['gemma_public', 0.0], ['gemma_private', 0.0]])\n"
"    print('placeholder submission.csv written (commit mode)')\n")

cells = [ md(intro), code(setup), code(writecell), code(serve) ]
nb = {"cells": cells,
      "metadata": {"kernelspec":{"name":"python3","display_name":"Python 3","language":"python"},
                   "language_info":{"name":"python","version":"3.11"}},
      "nbformat": 4, "nbformat_minor": 5}
json.dump(nb, open("kaggle_notebook.ipynb","w"), indent=1)
print("wrote kaggle_notebook.ipynb; attack.py src bytes:", len(src), "cells:", len(cells))
# guard: attack.py must not contain triple-single-quote which would break the r''' wrapper
assert "'''" not in src, "attack.py contains ''' which breaks the raw-string wrapper!"
print("no ''' collision — safe")
