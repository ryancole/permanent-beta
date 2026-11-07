//! Model backends: Claude Code in print mode (a Claude subscription), a recording that replays answers, and a
//! scripted model for tests.
//!
//! Remote calls are opt-in and logged (design §8): [`Cassette`] writes every live exchange, prompt and reply, to a
//! JSON Lines file, and the same file replays them, so corpus scores are repeatable without the model.

use crate::prompt::Prompt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

pub trait Model {
    /// The model's identity, part of every recording key: answers from different models never mix.
    fn name(&self) -> String;
    /// The raw reply text (the answer JSON) for `prompt`.
    fn complete(&self, prompt: &Prompt) -> Result<String, String>;
}

/// Claude through the Claude Code CLI in print mode (`claude -p`), which runs on the user's Claude
/// subscription once they've signed in with `/login`.
///
/// Every tool is disabled (`--tools ""`), MCP servers, settings and session persistence are off, and it runs in an
/// empty working directory, so a reply can only be text: nothing in a prompt can make it act. The answer schema
/// goes in as `--json-schema`.
pub struct ClaudeCode {
    pub program: PathBuf,
    /// e.g. `claude-opus-5-5`.
    pub model: String,
    /// Optional `--effort` level.
    pub effort: Option<String>,
}

impl ClaudeCode {
    fn workdir() -> Result<PathBuf, String> {
        let dir = std::env::temp_dir().join("pbeta-ai-empty");
        std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        Ok(dir)
    }
}

impl Model for ClaudeCode {
    fn name(&self) -> String {
        format!("claude-code:{}", self.model)
    }

    fn complete(&self, prompt: &Prompt) -> Result<String, String> {
        let mut cmd = Command::new(&self.program);
        cmd.args(["-p", "--output-format", "json", "--model", &self.model])
            .args([
                "--tools",
                "",
                "--strict-mcp-config",
                "--setting-sources",
                "",
            ])
            .arg("--no-session-persistence")
            .args(["--system-prompt", &prompt.system])
            .args(["--json-schema", &prompt.schema]);
        if let Some(e) = &self.effort {
            cmd.args(["--effort", e]);
        }
        let mut child = cmd
            .current_dir(Self::workdir()?)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("starting {}: {e}", self.program.display()))?;
        child
            .stdin
            .take()
            .ok_or("no stdin")?
            .write_all(prompt.user.as_bytes())
            .map_err(|e| format!("writing the prompt: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting for claude: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let v: Value = serde_json::from_str(stdout.trim()).map_err(|_| {
            format!(
                "claude exited {:?} without a JSON result: {}{}",
                out.status.code(),
                stdout.trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            )
        })?;
        if v["is_error"].as_bool() == Some(true) {
            return Err(format!(
                "claude: {}",
                v["result"].as_str().unwrap_or("error without a message")
            ));
        }
        // With --json-schema the validated object comes back as `structured_output`; fall back to the text.
        match &v["structured_output"] {
            Value::Object(_) => Ok(v["structured_output"].to_string()),
            _ => v["result"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "claude returned no result".to_owned()),
        }
    }
}

/// One recorded exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exchange {
    pub key: String,
    pub model: String,
    /// The prompt as sent, for audit (design §8: remote calls are logged).
    pub system: String,
    pub user: String,
    pub schema: String,
    pub reply: String,
}

/// Replays recorded answers by (model, prompt), and with a live model behind it, records new ones. Without a
/// live model a prompt that was never recorded is an error, never a guess.
pub struct Cassette {
    path: PathBuf,
    name: String,
    live: Option<Box<dyn Model>>,
    recorded: Mutex<HashMap<(String, String), String>>,
}

impl Cassette {
    /// `name` is the model identity to replay under; with `live`, it's taken from the live model.
    pub fn open(path: &Path, name: &str, live: Option<Box<dyn Model>>) -> Result<Self, String> {
        let mut recorded = HashMap::new();
        if path.exists() {
            let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
                let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
                if line.trim().is_empty() {
                    continue;
                }
                let x: Exchange = serde_json::from_str(&line)
                    .map_err(|e| format!("{} line {}: {e}", path.display(), i + 1))?;
                recorded.insert((x.model, x.key), x.reply);
            }
        }
        Ok(Self {
            path: path.to_owned(),
            name: live.as_ref().map_or_else(|| name.to_owned(), |m| m.name()),
            live,
            recorded: Mutex::new(recorded),
        })
    }

    pub fn len(&self) -> usize {
        self.recorded.lock().map(|r| r.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Model for Cassette {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn complete(&self, prompt: &Prompt) -> Result<String, String> {
        let key = (self.name.clone(), prompt.key());
        if let Some(r) = self.recorded.lock().ok().and_then(|r| r.get(&key).cloned()) {
            return Ok(r);
        }
        let Some(live) = &self.live else {
            return Err(format!(
                "not recorded for {} (key {}); run with a live model to record it",
                self.name,
                &key.1[..12]
            ));
        };
        let reply = live.complete(prompt)?;
        let x = Exchange {
            key: key.1.clone(),
            model: self.name.clone(),
            system: prompt.system.clone(),
            user: prompt.user.clone(),
            schema: prompt.schema.clone(),
            reply: reply.clone(),
        };
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        writeln!(f, "{}", serde_json::to_string(&x).unwrap_or_default())
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        if let Ok(mut r) = self.recorded.lock() {
            r.insert(key, reply.clone());
        }
        Ok(reply)
    }
}

/// A model that answers from a function, for tests.
pub struct Scripted<F: Fn(&Prompt) -> Result<String, String>>(pub F);

impl<F: Fn(&Prompt) -> Result<String, String>> Model for Scripted<F> {
    fn name(&self) -> String {
        "scripted".into()
    }
    fn complete(&self, prompt: &Prompt) -> Result<String, String> {
        (self.0)(prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn prompt(user: &str) -> Prompt {
        Prompt {
            system: "s".into(),
            user: user.into(),
            schema: "{}".into(),
            ids: vec!["c1".into()],
            candidates: vec![permanent_beta_model::Rva(0x10)],
        }
    }

    #[test]
    fn a_cassette_records_live_answers_and_replays_them_without_the_model() {
        let path =
            std::env::temp_dir().join(format!("pbeta-ai-cassette-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        let live = Scripted(|p: &Prompt| {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(format!("reply to {}", p.user))
        });
        let c = Cassette::open(&path, "", Some(Box::new(live))).unwrap();
        assert_eq!(c.complete(&prompt("a")).unwrap(), "reply to a");
        assert_eq!(c.complete(&prompt("a")).unwrap(), "reply to a");
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "the second ask is replayed"
        );

        // Replay only: recorded prompts answer, others are errors, and another model's recording doesn't count.
        let replay = Cassette::open(&path, "scripted", None).unwrap();
        assert_eq!(replay.complete(&prompt("a")).unwrap(), "reply to a");
        assert!(replay.complete(&prompt("b")).is_err());
        let other = Cassette::open(&path, "claude-code:x", None).unwrap();
        assert!(other.complete(&prompt("a")).is_err());

        // The log holds the prompt as sent.
        let log = std::fs::read_to_string(&path).unwrap();
        let x: Exchange = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        assert_eq!((x.user.as_str(), x.model.as_str()), ("a", "scripted"));
        let _ = std::fs::remove_file(&path);
    }
}
