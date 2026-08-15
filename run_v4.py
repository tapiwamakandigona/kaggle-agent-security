import subprocess,sys,time
t0=time.time()
r=subprocess.run([".venv/bin/python","-m","aicomp_sdk.cli.main","evaluate","redteam","submission/attack.py",
                  "--agent","deterministic","--budget-s","30","--env","gym","--verbosity","summary"],
                 capture_output=True,text=True,timeout=180)
out=r.stdout+r.stderr
for line in out.splitlines():
    if any(k in line.lower() for k in ["score","finding","candidate","overrun","unique","error","exceeded"]):
        print(line.strip())
print("WALL",round(time.time()-t0,1),"s")
