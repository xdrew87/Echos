/// Options derived from CLI flags, threaded through all network and beacon operations.
pub struct RuntimeOptions {
    /// Only true when --insecure-tls is explicitly passed.
    pub insecure_tls: bool,
    /// Per-connection/request timeout in seconds.
    pub timeout_secs: u64,
    pub dry_run: bool,
    pub json_output: bool,
    pub target_override: Option<String>,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            insecure_tls: false,
            timeout_secs: 10,
            dry_run: false,
            json_output: false,
            target_override: None,
        }
    }
}
