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

    pub fn nop() -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/dev/null")
            .expect("failed to open /dev/null");
        AuditLogger {
            file: Mutex::new(file),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn read_log(path: &str) -> Vec<serde_json::Value> {
        let mut f = File::open(path).unwrap();
        let mut contents = String::new();
        f.read_to_string(&mut contents).unwrap();
        contents
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn test_allow_writes_entry() {
        let dir = std::env::temp_dir().join(format!("audit-test-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let logger = AuditLogger::new(dir.to_str().unwrap()).unwrap();
        logger.allow("GET", "/_ping");

        let entries = read_log(dir.to_str().unwrap());
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e["decision"], "ALLOW");
        assert_eq!(e["method"], "GET");
        assert_eq!(e["uri"], "/_ping");
        assert_ne!(e["request_id"], "");
        assert_ne!(e["timestamp"], "");
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn test_deny_writes_entry() {
        let dir = std::env::temp_dir().join(format!("audit-test-deny-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let logger = AuditLogger::new(dir.to_str().unwrap()).unwrap();
        logger.deny("POST", "/containers/create", "exec denied by policy");

        let entries = read_log(dir.to_str().unwrap());
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e["decision"], "DENY");
        assert_eq!(e["method"], "POST");
        assert_eq!(e["uri"], "/containers/create");
        assert_eq!(e["reason"], "exec denied by policy");
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn test_multiple_entries() {
        let dir = std::env::temp_dir().join(format!("audit-test-multi-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let logger = AuditLogger::new(dir.to_str().unwrap()).unwrap();
        for _ in 0..5 {
            logger.allow("GET", "/version");
        }

        let entries = read_log(dir.to_str().unwrap());
        assert_eq!(entries.len(), 5);
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn test_nop_writes_nowhere() {
        let logger = AuditLogger::nop();
        logger.allow("GET", "/_ping");
        logger.deny("POST", "/containers/create", "denied");
    }
}
