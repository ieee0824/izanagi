"""Manual real-VM telemetry/HTTP/privacy/shell/resource check; see README.md here.
Never run automatically in unit tests: requires a separately prepared isolated VM.
"""
import os,subprocess,time,json,hashlib,threading,argparse,shutil,tomllib,sys,pty,termios,fcntl,struct,select,signal
from pathlib import Path
parser = argparse.ArgumentParser(description="Run a behavior smoke test against an explicitly prepared, isolated VM")
parser.add_argument("--directory", type=Path, required=True)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--config", type=Path, required=True)
args = parser.parse_args()
D = args.directory.resolve()
W = D / "workspace"
B = str(args.binary.resolve())
configuration = tomllib.loads(args.config.read_text())
assert configuration["sandbox"]["backend"] == "qemu"
assert configuration["sandbox"]["tracer"] == "vm-agent"
assert configuration["sandbox"]["require_auth"] is True
assert configuration["share"]["paths"] == [str(W)]
assert configuration["share"]["mount_point"] == "/workspace"
assert configuration["behavior"]["enabled"] is True
assert configuration["behavior"]["proxy_listen"] == "127.0.0.1:18080"
assert configuration["behavior"]["fixture_endpoint"] == "127.0.0.1:19090"
assert configuration["behavior"]["classifier"]["provider"] == "mock"
assert not configuration["behavior"]["classifier"].get("allow_export", False)
assert "IZANAGI_SECRET_FILE" in os.environ
assert W.is_dir(), "Prepare a dedicated guest-writable fixture directory"
assert not (D / "up-second.log").exists(), "Use a fresh artifact directory for each test"
for name in ["vm-client.py", "vm-receiver.py", "vm-mixed-writer.py"]:
    shutil.copy2(Path(__file__).resolve().parent / name, W / name.removeprefix("vm-"))
E = os.environ.copy()
E["TERM"] = "xterm-256color"
C = [B, "--config", str(args.config.resolve())]
I = Path.home() / ".izanagi/instances" / hashlib.sha256(str(W).encode()).hexdigest()
assert not (I / "session.json").exists(), "The fixture instance must be stopped"
owned = []
results = []
def record(name, **fields):
    value = dict(case=name, **fields)
    results.append(value)
    print(json.dumps(value), flush=True)
    (D / "shell-results.json").write_text(json.dumps(results, indent=2))
log=open(D/'up-second.log','wb');up=subprocess.Popen(C+['up'],cwd=W,env=E,stdout=log,stderr=log)
# Reap the child independently: down checks kill(pid, 0), which also sees zombies.
threading.Thread(target=up.wait,daemon=True).start()
def run(cmd):
 r=subprocess.run(C+['exec']+cmd,cwd=W,env=E,capture_output=True,timeout=100)
 assert r.returncode==0,(r.stdout,r.stderr)
 return r.stdout
samples=[]; sampling=threading.Event()
def sampler():
 while not sampling.is_set():
  data=subprocess.check_output(["ps","-axo","pid=,ppid=,rss=,pcpu=,comm="],text=True)
  for line in data.splitlines():
   fields=line.strip().split(None,4)
   if len(fields)==5 and (int(fields[0])==up.pid or int(fields[1])==up.pid):samples.append(dict(pid=int(fields[0]),rss_kib=int(fields[2]),cpu_percent=float(fields[3]),command=fields[4]))
  sampling.wait(.5)
threading.Thread(target=sampler,daemon=True).start()
class Shell:
 def __init__(self,name):
  self.name=name; self.out=b''; self.master,self.slave=pty.openpty(); self.result=D/(name+'.json'); self.pidfile=D/(name+'.pid')
  wrapper="""import os,sys,subprocess,termios,fcntl,json
from pathlib import Path
before=termios.tcgetattr(0); flags=fcntl.fcntl(0,fcntl.F_GETFL)
p=subprocess.Popen(sys.argv[3:]); Path(sys.argv[2]).write_text(str(p.pid)); code=p.wait()
Path(sys.argv[1]).write_text(json.dumps(dict(code=code,termios_restored=before==termios.tcgetattr(0),flags_restored=(flags & os.O_NONBLOCK)==(fcntl.fcntl(0,fcntl.F_GETFL) & os.O_NONBLOCK),flags_before=flags,flags_after=fcntl.fcntl(0,fcntl.F_GETFL))))
"""
  def setup(): os.setsid(); fcntl.ioctl(0,termios.TIOCSCTTY,0)
  self.p=subprocess.Popen([sys.executable,'-c',wrapper,str(self.result),str(self.pidfile)]+C+['shell'],cwd=W,env=E,stdin=self.slave,stdout=self.slave,stderr=self.slave,preexec_fn=setup); owned.append(self.p)
 def drain(self,seconds=.1):
  end=time.monotonic()+seconds
  while time.monotonic()<end:
   if select.select([self.master],[],[],min(.05,max(0,end-time.monotonic())))[0]:
    try: self.out+=os.read(self.master,65536)
    except OSError: break
 def raw(self):
  end=time.monotonic()+120
  while time.monotonic()<end:
   self.drain()
   if not termios.tcgetattr(self.slave)[3]&termios.ICANON:return
   if self.p.poll() is not None:raise AssertionError(self.out.decode(errors='replace'))
  raise TimeoutError('shell startup')
 def send(self,s): os.write(self.master,s.encode())
 def resize(self,r,c): fcntl.ioctl(self.slave,termios.TIOCSWINSZ,struct.pack('HHHH',r,c,0,0)); os.kill(int(self.pidfile.read_text()),signal.SIGWINCH)
 def expect(self,s,seconds=30):
  end=time.monotonic()+seconds
  while s.encode() not in self.out and time.monotonic()<end:self.drain()
  assert s.encode() in self.out,(s,self.out.decode(errors='replace'))
 def finish(self,code):
  end=time.monotonic()+60
  while self.p.poll() is None and time.monotonic()<end:self.drain()
  assert self.p.poll() is not None,'shell exit timeout'
  self.drain(); (D/(self.name+'.log')).write_bytes(self.out)
  r=json.loads(self.result.read_text()); assert r['code']==code and r['termios_restored'] and r['flags_restored'],r
  assert b'incompatible' not in self.out.lower(),self.out
  record(self.name,**r); os.close(self.master);os.close(self.slave)

try:
 end=time.monotonic()+120
 while not (I/'session.json').exists():
  assert up.poll() is None,(D/'up-second.log').read_text()
  assert time.monotonic()<end,'startup timeout'
  time.sleep(.2)
 print('VM_READY',flush=True)
 run(['/bin/sh','-c','python3 /workspace/receiver.py >/workspace/receiver.log 2>&1 & printf dummy >/workspace/dummy-credentials; sleep 1'])
 guest_before=run(['ps','-o','pid=,rss=,pcpu=,comm=','-C','izanagi-agent','-C','izanagi-http-capture']).decode()
 routine_out=run(['python3','/workspace/client.py','--routine']);assert b'VM_KEEP_ALIVE_POST_OK' in routine_out;print('VM_ROUTINE_POST_OK',flush=True)
 out=run(['python3','/workspace/client.py']);assert b'VM_KEEP_ALIVE_POST_OK' in out;print(out.decode(),flush=True)
 guest_after=run(['ps','-o','pid=,rss=,pcpu=,comm=','-C','izanagi-agent','-C','izanagi-http-capture']).decode()
 time.sleep(3)
 dirs=list((I/'logs/behavior').iterdir());latest=max(dirs,key=lambda p:p.stat().st_mtime)
 raw=''.join(f.read_text() for f in sorted(latest.glob('*.jsonl')));assert 'DO_NOT_LOG' not in raw
 records=[json.loads(l) for l in raw.splitlines()]
 assessments=[r['payload']['Assessment'] for r in records if 'Assessment' in r['payload']]
 classifications=[r['payload']['Classification'] for r in records if 'Classification' in r['payload']]
 assert len(assessments)==4,assessments
 assert all(a['snapshot']['upstream_bytes_written']>0 and a['snapshot']['transfer_outcome']=='completed' for a in assessments)
 assert all(a['snapshot']['process'] is not None for a in assessments),assessments
 routine_windows=[a for a in assessments if a['snapshot']['credential_access_attempts']==0]
 access_windows=[a for a in assessments if a['snapshot']['credential_access_attempts']==2]
 assert len(routine_windows)==2 and len(access_windows)==2,assessments
 assert all(a['snapshot']['credential_open_succeeded']==1 and a['snapshot']['credential_open_failed']==1 for a in access_windows),assessments
 assert all(a['snapshot']['credential_open_succeeded']==0 and a['snapshot']['credential_open_failed']==0 for a in routine_windows),assessments
 assert all(a['snapshot']['binding']=='confirmed_writer' and not a['snapshot']['quality']['issues'] for a in assessments),assessments
 assert all(a['status']=='classified' for a in classifications),classifications
 events=[r['payload']['Event'] for r in records if 'Event' in r['payload']]
 (D/'observed-events-second.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
 (D/'resources.json').write_text(json.dumps(dict(host_samples=samples,guest_before=guest_before,guest_after=guest_after,drops=[e['payload']['ObservationGap'] for e in events if isinstance(e['payload'],dict) and 'ObservationGap' in e['payload']]),indent=2))
 result={'session':latest.name,'canary_absent':True,'assessments':assessments,'classifications':classifications,'http_round_trip_ns':{mode:json.loads((W/('latency-'+mode+'.json')).read_text()) for mode in ['routine','access']}}
 (D/'results-second.json').write_text(json.dumps(result,indent=2));print('VM_TELEMETRY_CORRELATION_AND_PRIVACY_OK',flush=True)
 out=run(['python3','/workspace/mixed-writer.py']);assert out.count(b'VM_MIXED_WRITER_TRANSFER_OK')==2;print(out.decode(),flush=True)
 time.sleep(3)
 raw=''.join(f.read_text() for f in sorted(latest.glob('*.jsonl')));assert 'DO_NOT_LOG' not in raw
 records=[json.loads(l) for l in raw.splitlines()]
 positive_ids={a['snapshot']['window_id'] for a in assessments}
 negative=[r['payload']['Assessment'] for r in records if 'Assessment' in r['payload'] and r['payload']['Assessment']['snapshot']['window_id'] not in positive_ids]
 assert len(negative)==2,negative
 assert all(a['snapshot']['binding']=='unknown' and 'socket_shared' in a['snapshot']['quality']['issues'] for a in negative),negative
 negative_ids={a['snapshot']['window_id'] for a in negative}
 negative_classes=[r['payload']['Classification'] for r in records if 'Classification' in r['payload'] and r['payload']['Classification']['window_id'] in negative_ids]
 assert len(negative_classes)==2 and all(c['status']=='abstained' for c in negative_classes),negative_classes
 (D/'writer-negative-results.json').write_text(json.dumps(dict(assessments=negative,classifications=negative_classes),indent=2))
 events=[r['payload']['Event'] for r in records if 'Event' in r['payload']]
 (D/'observed-events-second.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
 print('VM_MIXED_WRITER_ABSTENTION_OK',flush=True)
 shell=Shell('behavior-existing-shell');shell.raw();shell.send("echo PROXY:$http_proxy; id -u\n");shell.expect('PROXY:http://127.0.0.1:18080');shell.resize(47,121);shell.send('stty size\n');shell.expect('47 121');shell.send('exit 7\n');shell.finish(7)
 print('VM_BEHAVIOR_SHELL_LIFECYCLE_OK',flush=True)
 stopped=subprocess.run(C+['down'],cwd=W,env=E,capture_output=True,timeout=30)
 assert stopped.returncode==0,(stopped.stdout,stopped.stderr)
 up.wait(timeout=30);assert up.returncode==0
 assert all(not (I/name).exists() for name in ['session.json','izanagi.pid','izanagi.lock'])
 log.close();log=open(D/'up-monitor-loss.log','wb')
 up=subprocess.Popen(C+['up'],cwd=W,env=E,stdout=log,stderr=log)
 threading.Thread(target=up.wait,daemon=True).start()
 end=time.monotonic()+120
 while not (I/'session.json').exists():
  assert up.poll() is None and time.monotonic()<end
  time.sleep(.2)
 idle=Shell('behavior-monitor-loss-shell');idle.raw()
 pending=subprocess.Popen(C+['exec','/bin/sh','-c','sleep 60'],cwd=W,env=E,stdout=subprocess.PIPE,stderr=subprocess.PIPE);owned.append(pending)
 time.sleep(1)
 rows=subprocess.check_output(['ps','-axo','pid=,ppid=,comm='],text=True).splitlines()
 qemu=[]
 for row in rows:
  fields=row.strip().split(None,2)
  if len(fields)==3 and int(fields[1])==up.pid and Path(fields[2]).name=='qemu-system-aarch64':qemu.append(int(fields[0]))
 assert len(qemu)==1,qemu
 started=time.monotonic();os.kill(qemu[0],signal.SIGTERM)
 up.wait(timeout=25);pending.communicate(timeout=25)
 assert up.returncode!=0 and pending.returncode!=0
 idle.finish(1)
 assert all(not (I/name).exists() for name in ['session.json','izanagi.pid','izanagi.lock'])
 record('behavior-monitor-loss-cleanup',seconds=time.monotonic()-started,up_code=up.returncode,exec_code=pending.returncode)
 print('VM_BEHAVIOR_MONITOR_LOSS_OK',flush=True)

finally:
 sampling.set()
 for process in owned:
  if process.poll() is None:
   process.terminate()
   process.wait(timeout=10)
 subprocess.run(C+['down'],cwd=W,env=E,capture_output=True,timeout=30);up.wait(timeout=30);log.close()
