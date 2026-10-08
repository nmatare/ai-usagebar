import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

spec = importlib.util.spec_from_file_location('handoff', Path(__file__).parents[1] / 'src/claude_desktop/remote_worker.py')
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


class RemoteHandoff(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='aiub-handoff-test-')
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.proc = Path('/proc')
        self.runtime = self.home / '.claude/remote/run/test-runtime'
        (self.runtime / 'children').mkdir(parents=True)
        self.executable = self.home / '.claude/remote/ccd-cli/test-python'
        self.executable.parent.mkdir(parents=True)
        shutil.copy2(sys.executable, self.executable)
        self.target = {'account_uuid': 'target-account', 'org_uuid': 'target-org'}
        self.sessions = []

    def spawn(self, token):
        identifier = str(uuid.uuid4())
        transcript = self.home / '.claude/projects/project' / (identifier + '.jsonl')
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text('original conversation\n')
        code = '''import pathlib,signal,sys,time,subprocess
p=pathlib.Path(sys.argv[1])
def stop(*unused):
 with p.open('a') as stream:stream.write('flushed before exit\\n')
 sys.exit(0)
signal.signal(signal.SIGTERM,stop)
job=subprocess.Popen(['/bin/sleep','120'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(job.pid,flush=True)
while True:time.sleep(1)
'''
        worker = subprocess.Popen([str(self.executable), '-c', code, str(transcript)],
                                  env=dict(os.environ, CLAUDE_CODE_OAUTH_TOKEN=token),
                                  stdout=subprocess.PIPE, text=True)
        background = int(worker.stdout.readline())
        worker.stdout.close()

        def cleanup():
            if worker.poll() is None:
                worker.terminate()
            worker.wait(timeout=5)
            try:
                os.kill(background, 15)
            except ProcessLookupError:
                pass
        self.addCleanup(cleanup)
        remote_id = str(uuid.uuid4())
        start = handoff.process_state(self.proc / str(worker.pid))[2]
        meta = {'pid': worker.pid, 'start': start, 'argv0': str(self.executable),
                'node': (self.proc / 'sys/kernel/random/boot_id').read_text().strip() + '/' + os.readlink('/proc/self/ns/pid'),
                'daemonPid': os.getpid(), 'daemonStart': handoff.process_state(self.proc / str(os.getpid()))[2]}
        (self.runtime / 'children' / (str(worker.pid) + '.json')).write_text(json.dumps(meta))
        with (self.runtime / 'remote-server.log').open('a') as stream:
            stream.write(f'2026/01/01 00:00:00 Process {remote_id} started, PID={worker.pid}, command={self.executable}\n')
        session = {'session_id': 'local_' + identifier, 'remote_id': remote_id,
                   'cli_session_id': identifier, 'transcript': str(transcript)}
        self.sessions.append(session)
        return worker, background, session

    def identity(self, token):
        if token in (b'new-token', b'refreshed-target-token'):
            return self.target
        if token == b'old-token':
            return {'account_uuid': 'outgoing-account', 'org_uuid': 'outgoing-org'}
        raise handoff.HandoffError('unknown account')

    def request(self):
        return {'target': self.target, 'sessions': self.sessions, 'transaction': uuid.uuid4().hex}

    def test_cross_account_stop_flushes_history_and_leaves_same_account_and_jobs_alive(self):
        old, job, session = self.spawn('old-token')
        correct, _, _ = self.spawn('new-token')
        refreshed, _, _ = self.spawn('refreshed-target-token')
        unrelated, _, _ = self.spawn('unrelated-token')
        self.sessions.pop()
        request = self.request()
        request['expected'] = handoff.inspect(request, self.home, self.proc, self.identity)
        self.assertEqual([r['state'] for r in request['expected']], ['mismatch', 'matched', 'matched'])
        staged = handoff.stage(request, self.home, self.proc, self.identity)
        self.assertEqual(len(staged), 1)
        result = handoff.stop(request, self.home, self.proc, self.identity)
        self.assertEqual(old.wait(timeout=3), 0)
        self.assertIsNone(correct.poll())
        self.assertIsNone(refreshed.poll())
        self.assertIsNone(unrelated.poll())
        self.assertTrue((self.proc / str(job)).exists())
        self.assertEqual(Path(result[0]['flushed_backup']).read_text(), 'original conversation\nflushed before exit\n')
        self.assertEqual(Path(result[0]['backup']).read_text(), 'original conversation\n')
        self.assertEqual(Path(result[0]['backup']).stat().st_mode & 0o777, 0o600)
        self.assertNotIn('old-token', json.dumps(result))
        self.assertEqual(handoff.stop(request, self.home, self.proc, self.identity)[0]['stop_state'], 'exited')

    def test_changed_process_identity_is_not_signalled_and_unknown_account_blocks_preflight(self):
        worker, _, _ = self.spawn('old-token')
        request = self.request()
        request['expected'] = handoff.inspect(request, self.home, self.proc, self.identity)
        handoff.stage(request, self.home, self.proc, self.identity)
        metadata = self.runtime / 'children' / (str(worker.pid) + '.json')
        document = json.loads(metadata.read_text())
        document['argv0'] = '/different/executable'
        metadata.write_text(json.dumps(document))
        with self.assertRaisesRegex(handoff.HandoffError, 'executable changed'):
            handoff.stop(request, self.home, self.proc, self.identity)
        self.assertIsNone(worker.poll())
        document['argv0'] = str(self.executable)
        metadata.write_text(json.dumps(document))
        unknown, _, _ = self.spawn('unknown-token')
        with self.assertRaisesRegex(handoff.HandoffError, 'unknown account'):
            handoff.inspect(self.request(), self.home, self.proc, self.identity)
        self.assertIsNone(unknown.poll())


if __name__ == '__main__':
    if sys.platform != 'linux':
        raise SystemExit('This integration suite requires Linux procfs and pidfd; run on Linux or an isolated SSH test host.')
    os.umask(0o077)
    unittest.main()
