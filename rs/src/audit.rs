use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

pub struct AuditLogger {
    file: Mutex<File>,
}

impl AuditLogger {
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(AuditLogger {
            file: Mutex::new(file),
        })
    }

    pub fn allow(&self, method: &str, uri: &str) {
        self.log("ALLOW", method, uri, "");
    }

    pub fn deny(&self, method: &str, uri: &str, reason: &str) {
        self.log("DENY", method, uri, reason);
    }

    fn log(&self, decision: &str, method: &str, uri: &str, reason: &str) {
        let request_id: String = {
            let mut bytes = [0u8; 8];
            rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        };
        let ts = chrono::Utc::now().to_rfc3339();
        let entry = serde_json::json!({
            "timestamp": ts,
            "request_id": request_id,
            "decision": decision,
            "method": method,
            "uri": uri,
            "reason": reason,
        });
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{}", entry);
        }
    }
}
