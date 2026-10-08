import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import sys
import urllib.error
import urllib.request


class HandoffError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise HandoffError(message)


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('x') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def process_state(proc):
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    return fields[0], int(fields[1]), fields[19]


def profile(token):
    request = urllib.request.Request(
        'https://api.anthropic.com/api/oauth/profile',
        headers={'Authorization': 'Bearer ' + token.decode(),
                 'anthropic-beta': 'oauth-2025-04-20'},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            document = json.load(response)
    except urllib.error.HTTPError as error:
        raise HandoffError('worker identity endpoint returned HTTP ' + str(error.code)) from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise HandoffError('worker identity endpoint unavailable') from None
    account = document.get('account', {}).get('uuid')
    organization = document.get('organization', {}).get('uuid')
    require(isinstance(account, str) and isinstance(organization, str),
            'worker identity endpoint omitted account or organization')
    return {'account_uuid': account, 'org_uuid': organization}


def live_worker(home, proc_root, runtime, remote_id, pid, uid, node):
    proc = proc_root / str(pid)
    try:
        state, parent, start = process_state(proc)
        if state == 'Z':
            return None
        meta_path = runtime / 'children' / (str(pid) + '.json')
        if not meta_path.exists():
            require(Path(os.readlink(proc / 'exe')).parent != home / '.claude/remote/ccd-cli',
                    'live Claude worker has no helper ownership record')
            return None
        require(meta_path.is_file() and not meta_path.is_symlink(),
                'helper ownership record is not a regular file')
        meta = json.loads(meta_path.read_text())
        if meta['start'] != start:
            require(Path(os.readlink(proc / 'exe')).parent != home / '.claude/remote/ccd-cli',
                    'live Claude worker start time disagrees with helper ownership record')
            return None
        executable = os.readlink(proc / 'exe')
        require(proc.stat().st_uid == uid and meta_path.stat().st_uid == uid,
                'worker owner differs from SSH user')
        require(meta['pid'] == pid and meta['start'] == start and meta['argv0'] == executable,
                'worker PID, start time or executable changed')
        require(meta['node'] == node, 'worker namespace or boot identity changed')
        require(Path(executable).parent == home / '.claude/remote/ccd-cli',
                'worker is not an installed Desktop Claude executable')
        daemon = proc_root / str(meta['daemonPid'])
        require(parent == meta['daemonPid'] and process_state(daemon)[2] == meta['daemonStart'],
                'worker is no longer owned by its recorded helper')
        environment = dict(part.split(b'=', 1) for part in (proc / 'environ').read_bytes().split(b'\0')
                           if b'=' in part)
        token = environment.get(b'CLAUDE_CODE_OAUTH_TOKEN')
        require(bool(token), 'Desktop worker has no inference credential')
        record = {'remote_id': remote_id, 'pid': pid, 'start': start, 'owner': uid,
                  'node': node, 'executable': executable, 'runtime': runtime.name,
                  'daemon_pid': parent, 'daemon_start': meta['daemonStart'],
                  'fingerprint': hashlib.sha256(token).hexdigest()}
        return record, token
    except (FileNotFoundError, ProcessLookupError):
        # A missing metadata/daemon/environment file is not proof the PID exited.
        require(not proc.exists(), 'live worker verification was interrupted')
        return None


def inventory(home, proc_root):
    mappings = {}
    latest = {}
    runtimes = list((home / '.claude/remote/run').glob('*'))
    for runtime in runtimes:
        if not runtime.is_dir() or runtime.is_symlink():
            continue
        for logfile in runtime.glob('remote-server.log*'):
            with logfile.open(errors='replace') as stream:
                for line in stream:
                    match = re.search(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*Process ([0-9a-f-]+) started, PID=(\d+), command=(\S+)', line)
                    if match:
                        key = runtime, int(match[3])
                        stamp, remote_id = match[1], match[2]
                        previous = latest.get(key)
                        require(previous is None or previous[0] != stamp or previous[1] == remote_id,
                                'ambiguous process-start records for a reused PID')
                        if previous is None or stamp > previous[0]:
                            latest[key] = stamp, remote_id
    for key, (_, remote_id) in latest.items():
        mappings.setdefault(remote_id, set()).add(key)
    return mappings, runtimes


def inspect(request, home, proc_root, identity_lookup=profile):
    require(proc_root.is_dir(), 'remote handoff requires Linux procfs')
    uid = os.getuid()
    node = (proc_root / 'sys/kernel/random/boot_id').read_text().strip() + '/' + os.readlink(proc_root / 'self/ns/pid')
    mappings, runtimes = inventory(home, proc_root)
    identities = {}
    results = []
    for session in request['sessions']:
        remote_id = session['remote_id']
        live = []
        for runtime, pid in mappings.get(remote_id, set()):
            worker = live_worker(home, proc_root, runtime, remote_id, pid, uid, node)
            if worker:
                live.append(worker)
        require(len(live) <= 1, 'remote process ID maps to multiple live workers')
        if not live:
            # Log rotation can remove a mapping while the process is still alive.
            # Refuse ambiguity instead of assuming a still-running worker is gone.
            if remote_id not in mappings:
                for runtime in runtimes:
                    for child in (runtime / 'children').glob('*.json'):
                        meta = json.loads(child.read_text())
                        proc = proc_root / str(meta['pid'])
                        if proc.exists() and process_state(proc)[2] == meta['start']:
                            require(any((runtime, meta['pid']) in refs for refs in mappings.values()),
                                    'live helper child has no process-start mapping')
            results.append(dict(session, state='exited'))
            continue
        worker, token = live[0]
        fingerprint = worker['fingerprint']
        if fingerprint not in identities:
            identities[fingerprint] = identity_lookup(token)
        identity = identities[fingerprint]
        transcript = session.get('transcript')
        cli_id = session.get('cli_session_id')
        require(transcript and cli_id, 'live session lacks a stable transcript ID/path')
        path = Path(transcript)
        require(path.is_absolute() and path.name == cli_id + '.jsonl'
                and path.is_relative_to(home / '.claude/projects')
                and path.resolve().is_relative_to((home / '.claude/projects').resolve())
                and path.is_file() and not path.is_symlink() and path.stat().st_uid == uid,
                'live session transcript is missing or outside the SSH user project store')
        state = 'matched' if identity == request['target'] else 'mismatch'
        results.append(dict(session, **worker, **identity, state=state,
                            history_bytes=path.stat().st_size))
    return results


def same_worker(expected, actual):
    keys = ('session_id', 'remote_id', 'pid', 'start', 'owner', 'node', 'executable',
            'runtime', 'daemon_pid', 'daemon_start', 'fingerprint', 'account_uuid',
            'org_uuid', 'cli_session_id', 'transcript')
    return all(expected[key] == actual[key] for key in keys)


def checked_backup_path(home, transaction):
    require(re.fullmatch(r'[a-zA-Z0-9-]{1,100}', transaction) is not None,
            'invalid handoff transaction ID')
    root = home / '.claude/backups'
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not root.is_symlink() and root.stat().st_uid == os.getuid(),
            'remote backup root is not owned by SSH user')
    return root / ('ai-usagebar-' + transaction)


def stage(request, home, proc_root, identity_lookup=profile):
    actual = inspect(request, home, proc_root, identity_lookup)
    expected = {row['session_id']: row for row in request['expected']}
    selected = []
    for row in actual:
        old = expected[row['session_id']]
        if row['state'] == 'exited':
            continue
        require(same_worker(old, row), 'worker changed since handoff preflight')
        if row['state'] == 'mismatch':
            selected.append(row)
    backup = checked_backup_path(home, request['transaction'])
    backup.mkdir(mode=0o700)
    for row in selected:
        destination = backup / (row['session_id'] + '.before.jsonl')
        shutil.copyfile(row['transcript'], destination)
        os.chmod(destination, 0o600)
        row['backup'] = str(destination)
        row['stop_state'] = 'prepared'
    atomic_json(backup / 'journal.json', selected)
    return selected


def stop(request, home, proc_root, identity_lookup=profile):
    backup = checked_backup_path(home, request['transaction'])
    journal_path = backup / 'journal.json'
    require(not backup.is_symlink() and backup.stat().st_uid == os.getuid(),
            'remote handoff directory is not owned by SSH user')
    rows = json.loads(journal_path.read_text())
    actual = {row['session_id']: row for row in inspect(request, home, proc_root, identity_lookup)}
    for old in rows:
        row = actual[old['session_id']]
        if row['state'] != 'exited':
            require(same_worker(old, row), 'worker changed after transcript backup')
    for old in rows:
        row = actual[old['session_id']]
        if row['state'] != 'exited':
            # pidfd pins the exact process; a reused numeric PID can never be signalled.
            try:
                descriptor = os.pidfd_open(row['pid'])
            except ProcessLookupError:
                descriptor = None
            if descriptor is not None:
                try:
                    runtime = home / '.claude/remote/run' / row['runtime']
                    checked = live_worker(home, proc_root, runtime, row['remote_id'],
                                          row['pid'], row['owner'], row['node'])
                    require(checked is not None and all(checked[0][k] == row[k] for k in checked[0]),
                            'worker changed immediately before graceful stop')
                    old['stop_state'] = 'signal_pending'
                    atomic_json(journal_path, rows)
                    signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                    old['stop_state'] = 'signal_sent'
                    atomic_json(journal_path, rows)
                    ready, _, _ = select.select([descriptor], [], [], 15)
                    require(bool(ready), 'worker did not stop within 15 seconds; no forced kill')
                finally:
                    os.close(descriptor)
        old['stop_state'] = 'exited'
        destination = backup / (old['session_id'] + '.flushed.jsonl')
        shutil.copyfile(old['transcript'], destination)
        os.chmod(destination, 0o600)
        old['flushed_backup'] = str(destination)
        atomic_json(journal_path, rows)
    return rows


def main():
    os.umask(0o077)
    request = json.load(sys.stdin)
    home = Path.home()
    proc_root = Path('/proc')
    try:
        require(sys.version_info >= (3, 9), 'remote handoff requires Python 3.9 or newer')
        for session in request['sessions']:
            require(re.fullmatch(r'local_[0-9a-f-]{36}', session['session_id']) is not None,
                    'invalid Desktop session ID')
            require(re.fullmatch(r'[0-9a-f-]{36}', session['remote_id']) is not None,
                    'invalid helper process ID')
        action = request['action']
        require(action in ('inspect', 'stage', 'stop'), 'unsupported remote handoff action')
        result = {'inspect': inspect, 'stage': stage, 'stop': stop}[action](request, home, proc_root)
        print(json.dumps({'workers': result}))
    except HandoffError as error:
        print(json.dumps({'error': str(error)}))
        sys.exit(1)
    except Exception as error:
        # Never include credential-bearing request data or HTTP bodies in diagnostics.
        print(json.dumps({'error': 'remote handoff failed: ' + type(error).__name__}))
        sys.exit(1)


if __name__ == '__main__':
    main()
