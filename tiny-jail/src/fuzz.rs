use crate::error::JailError;
use crate::options::FuzzOptions;

// ============================================================================
// FUZZ PROFILE
// ============================================================================

/// Execute a command in fuzzing mode (not yet implemented).
pub fn fuzz_exec(_options: FuzzOptions) -> Result<(), JailError> {
    Err(JailError::FuzzingNotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::FuzzOptions;

    #[test]
    fn test_fuzz_exec() {
        let options = FuzzOptions {
            exec: vec!["true".to_string()],
            env: false,
            output: None,
            iterations: 100,
            threads: 1,
            batch: false,
        };
        let result = fuzz_exec(options);
        assert!(matches!(result, Err(JailError::FuzzingNotImplemented)));
    }
}
