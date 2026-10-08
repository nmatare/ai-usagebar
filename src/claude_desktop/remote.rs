use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Paths, SwitchPlan, active_account_uuid, load_profiles};
use crate::cache::atomic_write;
use crate::error::{AppError, Result};

const WORKER: &str = include_str!("remote_worker.py");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Host {
    #[serde(rename = "sshHost")]
    name: String,
    #[serde(rename = "sshPort")]
    port: Option<u16>,
    #[serde(rename = "sshIdentityFile")]
    identity_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Session {
    session_id: String,
    remote_id: String,
    cli_session_id: Option<String>,
    transcript: Option<String>,
    host: Host,
    index: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Identity {
    account_uuid: String,
    org_uuid: String,
}

#[derive(Serialize)]
pub struct Handoff {
    pub target: Identity,
    source: String,
    transaction: String,
    sessions: Vec<Session>,
    pub workers: Vec<Value>,
    verification: Vec<Value>,
    phase: String,
}

fn fail(message: impl Into<String>) -> AppError {
    AppError::Other(message.into())
}

fn read_json(path: &Path) -> Result<Value> {
    let bytes = std::fs::read(path).map_err(|error| AppError::io_at(path, error))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| fail(format!("SSH session lacks {key}")))
}

fn safe_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|id| id.len() == 36 && id.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-'))
}

pub fn discover(paths: &Paths) -> Result<(Identity, Vec<Session>)> {
    let account_uuid = active_account_uuid(&paths.config_json())
        .ok_or_else(|| fail("cannot identify the active Desktop account"))?;
    let profile = load_profiles(&paths.profiles_dir)
        .into_iter()
        .find(|p| p.account_uuid == account_uuid)
        .ok_or_else(|| {
            fail("active Desktop account has no saved profile for SSH session discovery")
        })?;
    let org_uuid = profile
        .org_uuid
        .ok_or_else(|| fail("active Desktop profile has no organization"))?;
    let identity = Identity {
        account_uuid,
        org_uuid,
    };
    let root = paths
        .sessions_root()
        .join(&identity.account_uuid)
        .join(&identity.org_uuid);
    let mut sessions = Vec::new();
    if !root.exists() {
        return Ok((identity, sessions));
    }
    for entry in std::fs::read_dir(&root).map_err(|e| AppError::io_at(&root, e))? {
        let path = entry.map_err(|e| AppError::io_at(&root, e))?.path();
        if path.extension().is_none_or(|ext| ext != "json")
            || !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("local_"))
        {
            continue;
        }
        let doc = read_json(&path)?;
        let Some(remote_id) = doc["sshRemoteProcessId"].as_str() else {
            continue;
        };
        let session_id = text(&doc, "sessionId")?;
        if !safe_id(session_id, "local_")
            || !safe_id(remote_id, "")
            || path.file_stem().and_then(|name| name.to_str()) != Some(session_id)
        {
            return Err(fail("invalid SSH session/process ID in Desktop index"));
        }
        if let Some(reattach_id) = doc["sshReattach"]["processId"].as_str()
            && reattach_id != remote_id
        {
            return Err(fail("Desktop SSH reconnect IDs disagree"));
        }
        let host: Host = serde_json::from_value(doc["sshConfig"].clone())?;
        host.validate()?;
        sessions.push(Session {
            session_id: session_id.into(),
            remote_id: remote_id.into(),
            cli_session_id: doc["cliSessionId"].as_str().map(str::to_string),
            transcript: doc["sshRemoteTranscriptPath"].as_str().map(str::to_string),
            host,
            index: path,
        });
    }
    sessions.sort_by(|a, b| a.session_id.cmp(&b.session_id));
    Ok((identity, sessions))
}

impl Host {
    fn validate(&self) -> Result<()> {
        if self.name.starts_with('-')
            || self.name.is_empty()
            || !self
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".@_:-[]".contains(&c))
            || self.port == Some(0)
        {
            return Err(fail("invalid SSH host or port in Desktop session"));
        }
        if let Some(identity) = &self.identity_file
            && (!identity.is_absolute() || !identity.is_file())
        {
            return Err(fail("SSH identity file must be an existing absolute path"));
        }
        Ok(())
    }

    fn call(&self, request: &Value) -> Result<Vec<Value>> {
        self.validate()?;
        let mut command = Command::new("/usr/bin/ssh");
        command.args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "StrictHostKeyChecking=yes",
        ]);
        if let Some(port) = self.port {
            command.args(["-p", &port.to_string()]);
        }
        if let Some(identity) = &self.identity_file {
            command.arg("-i").arg(identity);
        }
        // Only fixed source code goes into the remote shell; session data goes over stdin.
        let script = format!("python3 -c '{}'", WORKER.replace('\'', "'\\''"));
        command.arg("--").arg(&self.name).arg(script);
        execute(command, request, Duration::from_secs(120))
    }
}

fn execute(mut command: Command, request: &Value, timeout: Duration) -> Result<Vec<Value>> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| fail(format!("could not start SSH handoff: {e}")))?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| fail("SSH handoff stdin unavailable"))?;
    let bytes = serde_json::to_vec(request)?;
    let writer = std::thread::spawn(move || input.write_all(&bytes));
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fail("SSH handoff stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| fail("SSH handoff stderr unavailable"))?;
    let read = |mut stream: Box<dyn std::io::Read + Send>| {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).map(|_| bytes)
    };
    let out = std::thread::spawn(move || read(Box::new(stdout)));
    let err = std::thread::spawn(move || read(Box::new(stderr)));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > timeout {
            child.kill()?;
            child.wait()?;
            return Err(fail(
                "SSH handoff timed out; inspect its journal before retrying",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    writer.join().map_err(|_| fail("SSH writer failed"))??;
    let stdout = out.join().map_err(|_| fail("SSH output reader failed"))??;
    let stderr = err.join().map_err(|_| fail("SSH error reader failed"))??;
    let response: Value = serde_json::from_slice(&stdout).map_err(|_| {
        fail(format!(
            "SSH handoff returned no valid response ({}): {}",
            status,
            crate::display::sanitize_untrusted_line(&String::from_utf8_lossy(&stderr))
        ))
    })?;
    if !status.success() || response.get("error").is_some() {
        return Err(fail(format!(
            "SSH handoff: {}",
            response["error"]
                .as_str()
                .unwrap_or("remote command failed")
        )));
    }
    response["workers"]
        .as_array()
        .cloned()
        .ok_or_else(|| fail("SSH handoff omitted worker results"))
}

impl Handoff {
    pub fn plan(paths: &Paths, target: Identity) -> Result<Self> {
        let (source, sessions) = discover(paths)?;
        let mut handoff = Self {
            target,
            source: source.account_uuid,
            transaction: format!(
                "{}-{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%S%f"),
                std::process::id()
            ),
            sessions,
            workers: Vec::new(),
            verification: Vec::new(),
            phase: "inspected".into(),
        };
        for (host, sessions) in handoff.groups() {
            let request =
                json!({"action": "inspect", "sessions": sessions, "target": handoff.target});
            handoff.workers.extend(host.call(&request)?);
        }
        Ok(handoff)
    }

    pub fn for_switch(paths: &Paths, plan: &SwitchPlan) -> Result<Option<Self>> {
        // Pure local-only installs and test fixtures have no remote helper state.
        // A live SSH index without it is unsafe, not an empty handoff.
        let sessions_root = paths.sessions_root();
        if !paths.data_dir.join("ssh-remote-server-state.json").exists() {
            if !sessions_root.exists() {
                return Ok(None);
            }
            for account in std::fs::read_dir(&sessions_root)
                .map_err(|error| AppError::io_at(&sessions_root, error))?
            {
                let account = account
                    .map_err(|e| AppError::io_at(&sessions_root, e))?
                    .path();
                if Some(account.file_name().unwrap().to_string_lossy().as_ref())
                    != active_account_uuid(&paths.config_json()).as_deref()
                {
                    continue;
                }
                for org in std::fs::read_dir(&account).map_err(|e| AppError::io_at(&account, e))? {
                    let org = org.map_err(|e| AppError::io_at(&account, e))?.path();
                    for index in std::fs::read_dir(&org).map_err(|e| AppError::io_at(&org, e))? {
                        let index = index.map_err(|e| AppError::io_at(&org, e))?.path();
                        if index.extension().is_some_and(|ext| ext == "json")
                            && read_json(&index)?.get("sshRemoteProcessId").is_some()
                        {
                            return Err(fail(
                                "SSH session exists without Desktop remote helper state",
                            ));
                        }
                    }
                }
            }
            return Ok(None);
        }
        let org_uuid = plan
            .target
            .org_uuid
            .clone()
            .ok_or_else(|| fail("target account has no SSH organization"))?;
        let handoff = Self::plan(
            paths,
            Identity {
                account_uuid: plan.target.account_uuid.clone(),
                org_uuid,
            },
        )?;
        Ok(Some(handoff))
    }

    fn groups(&self) -> BTreeMap<Host, Vec<Session>> {
        let mut groups: BTreeMap<Host, Vec<Session>> = BTreeMap::new();
        for session in &self.sessions {
            groups
                .entry(session.host.clone())
                .or_default()
                .push(session.clone());
        }
        groups
    }

    fn checkpoint(&mut self, paths: &Paths, phase: &str) -> Result<()> {
        self.phase = phase.into();
        atomic_write(
            &paths
                .backups_dir
                .join(format!("remote-{}.json", self.transaction)),
            &serde_json::to_vec_pretty(self)?,
        )
    }

    pub fn stop(&mut self, paths: &Paths) -> Result<()> {
        let (current, sessions) = discover(paths)?;
        if current.account_uuid != self.source || sessions != self.sessions {
            return Err(fail(
                "Desktop SSH sessions changed during handoff; account was not switched",
            ));
        }
        self.checkpoint(paths, "backed_up")?;
        let groups = self.groups();
        // Stage every host before stopping any worker.
        for (host, sessions) in &groups {
            if !self.workers.iter().any(|w| {
                w["state"] == "mismatch" && sessions.iter().any(|s| w["session_id"] == s.session_id)
            }) {
                continue;
            }
            let expected: Vec<_> = self
                .workers
                .iter()
                .filter(|w| sessions.iter().any(|s| w["session_id"] == s.session_id))
                .collect();
            host.call(
                &json!({"action": "stage", "sessions": sessions, "target": self.target,
                "transaction": self.transaction, "expected": expected}),
            )?;
        }
        self.checkpoint(paths, "remote_backups_complete")?;
        for (host, sessions) in groups {
            if !self.workers.iter().any(|w| {
                w["state"] == "mismatch" && sessions.iter().any(|s| w["session_id"] == s.session_id)
            }) {
                continue;
            }
            self.checkpoint(paths, "stopping_workers")?;
            let stopped = host.call(
                &json!({"action": "stop", "sessions": sessions, "target": self.target,
                "transaction": self.transaction}),
            )?;
            for row in stopped {
                let existing = self
                    .workers
                    .iter_mut()
                    .find(|w| w["session_id"] == row["session_id"])
                    .ok_or_else(|| fail("unexpected worker in stop response"))?;
                *existing = row;
            }
            self.checkpoint(paths, "host_workers_stopped")?;
        }
        self.checkpoint(paths, "workers_stopped")
    }

    pub fn detach(&mut self, paths: &Paths) -> Result<usize> {
        let mut count = 0;
        for session in &self.sessions {
            let worker = self
                .workers
                .iter()
                .find(|w| w["session_id"] == session.session_id)
                .ok_or_else(|| fail("missing handoff worker result"))?;
            if worker["state"] == "matched" {
                continue;
            }
            if worker["state"] != "exited" && worker["stop_state"] != "exited" {
                return Err(fail(
                    "cannot reset reconnect metadata for a worker that has not exited",
                ));
            }
            let target = paths
                .sessions_root()
                .join(&self.target.account_uuid)
                .join(&self.target.org_uuid)
                .join(format!("{}.json", session.session_id));
            let mut indexes = vec![session.index.clone(), target];
            indexes.sort();
            indexes.dedup();
            for path in indexes {
                if !path.exists() {
                    continue;
                }
                let mut doc = read_json(&path)?;
                if doc["sshRemoteProcessId"] != session.remote_id {
                    continue;
                }
                if doc["cliSessionId"].as_str() != session.cli_session_id.as_deref() {
                    return Err(fail(
                        "transcript ID changed before reconnect metadata reset",
                    ));
                }
                let object = doc
                    .as_object_mut()
                    .ok_or_else(|| fail("session index is not an object"))?;
                object.remove("sshRemoteProcessId");
                object.remove("sshReattach");
                atomic_write(&path, &serde_json::to_vec_pretty(&doc)?)?;
                count += 1;
            }
        }
        self.checkpoint(paths, "switched_awaiting_native_reconnect")?;
        Ok(count)
    }

    pub fn verify(&mut self, paths: &Paths) -> Result<(usize, usize)> {
        self.checkpoint(paths, "switched_verification_incomplete")?;
        if active_account_uuid(&paths.config_json()).as_deref() != Some(&self.target.account_uuid) {
            return Err(fail(
                "Desktop login changed during post-switch verification",
            ));
        }
        let current = status(paths)?;
        if current.target != self.target {
            return Err(fail(
                "Desktop organization differs from the selected account",
            ));
        }
        self.verification = current.workers;
        if self
            .verification
            .iter()
            .any(|row| row["state"] == "mismatch")
        {
            self.checkpoint(paths, "switched_worker_identity_mismatch")?;
            return Err(fail(
                "Desktop login switched, but a live worker still has another account; no further workers were stopped",
            ));
        }
        let mut verified = 0;
        let mut pending = 0;
        for old in &self.workers {
            if old["state"] != "mismatch" {
                continue;
            }
            let new = self
                .verification
                .iter()
                .find(|row| row["session_id"] == old["session_id"]);
            match new {
                Some(new)
                    if new["state"] == "matched" && new["fingerprint"] != old["fingerprint"] =>
                {
                    verified += 1
                }
                Some(new) if new["state"] != "exited" => {
                    self.checkpoint(paths, "switched_worker_identity_mismatch")?;
                    return Err(fail(
                        "Desktop login switched, but a reconnected worker still has an unexpected identity; no further workers were stopped",
                    ));
                }
                _ => pending += 1,
            }
        }
        self.checkpoint(
            paths,
            if pending == 0 {
                "worker_identities_verified"
            } else {
                "switched_awaiting_native_reconnect"
            },
        )?;
        Ok((verified, pending))
    }
}

pub fn status(paths: &Paths) -> Result<Handoff> {
    let (identity, _) = discover(paths)?;
    Handoff::plan(paths, identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "local_11111111-1111-1111-1111-111111111111";
    const PROCESS: &str = "22222222-2222-2222-2222-222222222222";
    const CLI: &str = "33333333-3333-3333-3333-333333333333";

    fn fixture(root: &Path) -> Paths {
        let paths = Paths::at(
            root.join("data"),
            root.join("profiles"),
            root.join("backups"),
        );
        atomic_write(
            &paths.config_json(),
            &serde_json::to_vec(&json!({"lastKnownAccountUuid": "active"})).unwrap(),
        )
        .unwrap();
        atomic_write(
            &paths.profiles_dir.join("active/meta.json"),
            &serde_json::to_vec(&json!({"accountUuid":"active", "orgUuid":"current-org"})).unwrap(),
        )
        .unwrap();
        let doc = json!({"sessionId":SESSION, "cliSessionId":CLI, "sshRemoteProcessId":PROCESS,
            "sshConfig":{"sshHost":"owner@test-host"}, "sshReattach":{"processId":PROCESS},
            "sshRemoteTranscriptPath":format!("/home/owner/.claude/projects/project/{CLI}.jsonl"),
            "draft":{"text":"unsent request"}, "completedTurns":17, "lastActivityAt":1234,
            "error":"preserve pending failed request", "isStarred":true});
        for account_org in [
            "active/current-org",
            "active/stale-org",
            "target/target-org",
        ] {
            atomic_write(
                &paths
                    .sessions_root()
                    .join(account_org)
                    .join(format!("{SESSION}.json")),
                &serde_json::to_vec(&doc).unwrap(),
            )
            .unwrap();
        }
        paths
    }

    #[test]
    fn discovery_and_reconnect_reset_preserve_current_scope_drafts_and_transcript_ids() {
        let root = tempfile::tempdir().unwrap();
        let paths = fixture(root.path());
        let (_, sessions) = discover(&paths).unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].index.to_string_lossy().contains("current-org"));
        let original = read_json(&sessions[0].index).unwrap();
        let stale = paths
            .sessions_root()
            .join("active/stale-org")
            .join(format!("{SESSION}.json"));
        let stale_bytes = std::fs::read(&stale).unwrap();
        let mut handoff = Handoff {
            target: Identity {
                account_uuid: "target".into(),
                org_uuid: "target-org".into(),
            },
            source: "active".into(),
            transaction: "test".into(),
            sessions,
            workers: vec![json!({"session_id":SESSION,"state":"mismatch","stop_state":"exited"})],
            verification: Vec::new(),
            phase: "workers_stopped".into(),
        };
        assert_eq!(handoff.detach(&paths).unwrap(), 2);
        let mut expected = original;
        expected
            .as_object_mut()
            .unwrap()
            .remove("sshRemoteProcessId");
        expected.as_object_mut().unwrap().remove("sshReattach");
        assert_eq!(read_json(&handoff.sessions[0].index).unwrap(), expected);
        assert_eq!(
            read_json(
                &paths
                    .sessions_root()
                    .join("target/target-org")
                    .join(format!("{SESSION}.json"))
            )
            .unwrap(),
            expected
        );
        assert_eq!(std::fs::read(stale).unwrap(), stale_bytes);
        assert_eq!(
            read_json(&paths.backups_dir.join("remote-test.json")).unwrap()["phase"],
            "switched_awaiting_native_reconnect"
        );
    }

    #[test]
    fn changed_session_blocks_stop_and_unconfirmed_exit_blocks_metadata_reset() {
        let root = tempfile::tempdir().unwrap();
        let paths = fixture(root.path());
        let (_, sessions) = discover(&paths).unwrap();
        let mut handoff = Handoff {
            target: Identity {
                account_uuid: "target".into(),
                org_uuid: "target-org".into(),
            },
            source: "active".into(),
            transaction: "test".into(),
            sessions,
            workers: vec![
                json!({"session_id":SESSION,"state":"mismatch","stop_state":"signal_sent"}),
            ],
            verification: Vec::new(),
            phase: "stopping_workers".into(),
        };
        assert!(
            handoff
                .detach(&paths)
                .unwrap_err()
                .to_string()
                .contains("has not exited")
        );
        let index = handoff.sessions[0].index.clone();
        let mut changed = read_json(&index).unwrap();
        changed["sshRemoteProcessId"] = json!("44444444-4444-4444-4444-444444444444");
        changed["sshReattach"]["processId"] = changed["sshRemoteProcessId"].clone();
        atomic_write(&index, &serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            handoff
                .stop(&paths)
                .unwrap_err()
                .to_string()
                .contains("changed during handoff")
        );
        assert!(!paths.backups_dir.exists());
        assert_eq!(read_json(&index).unwrap(), changed);
    }
}
