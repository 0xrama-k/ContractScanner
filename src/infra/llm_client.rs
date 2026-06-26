//! Minimal OpenAI-compatible chat client (Section 4). One provider via this
//! client; on failure the caller degrades to Slither-only text (LLM_FAILED).

use std::time::Duration;

use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("llm transport error: {0}")]
    Transport(String),
    #[error("llm http {0}: {1}")]
    Status(u16, String),
    #[error("llm response parse error: {0}")]
    Parse(String),
    #[error("llm returned no content")]
    Empty,
}

pub struct LlmClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
}

impl LlmClient {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        model: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, LlmError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| LlmError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            model: model.into(),
        })
    }

    /// Single chat completion; returns the assistant message content.
    pub async fn chat(&self, system: &str, user: &str) -> Result<String, LlmError> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = json!({
            "model": self.model,
            "temperature": 0.2,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Transport(e.to_string()))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| LlmError::Transport(e.to_string()))?;

        if !status.is_success() {
            // Truncate provider error bodies to keep logs sane.
            let snippet: String = text.chars().take(300).collect();
            return Err(LlmError::Status(status.as_u16(), snippet));
        }

        let v: Value = serde_json::from_str(&text).map_err(|e| LlmError::Parse(e.to_string()))?;
        v["choices"][0]["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or(LlmError::Empty)
    }
}
