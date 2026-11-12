#!/usr/bin/env python3
"""Root-only provisioning helper: renew one fixed read-only ServiceAccount.

No arguments, candidate paths or environment-provided commands are accepted.
The daemon never invokes this helper and never receives administrator config.
"""
import grp,json,os,pwd,subprocess,tempfile
from pathlib import Path
import yaml

def main():
    if os.geteuid()!=0:raise SystemExit('root provisioning identity required')
    path=Path('/etc/change-guard/kubeconfig')
    current=yaml.safe_load(path.read_text())
    if not isinstance(current,dict) or len(current.get('users',[]))!=1:
        raise SystemExit('unexpected service kubeconfig structure')
    command=['/usr/bin/kubectl','--kubeconfig=/etc/kubernetes/admin.conf','--request-timeout=20s',
             '-n','change-guard','create','token','change-guard','--duration=12h']
    result=subprocess.run(command,capture_output=True,text=True,timeout=30,
                          env={'PATH':'/usr/bin:/bin','HOME':'/root'},check=False)
    if result.returncode:raise SystemExit('fixed ServiceAccount TokenRequest failed')
    token=result.stdout.strip()
    if token.count('.')!=2:raise SystemExit('TokenRequest returned malformed credential')
    current['users'][0]['user']={'token':token}
    uid=pwd.getpwnam('change-guard').pw_uid;gid=grp.getgrnam('change-guard').gr_gid
    fd,temporary=tempfile.mkstemp(prefix='.kubeconfig-',dir=str(path.parent))
    try:
        os.fchmod(fd,0o600);os.fchown(fd,uid,gid)
        with os.fdopen(fd,'w') as handle:
            yaml.safe_dump(current,handle,sort_keys=False);handle.flush();os.fsync(handle.fileno())
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    print(json.dumps({'renewed':'change-guard/change-guard','requested_lifetime':'12h'}))

if __name__=='__main__':main()
