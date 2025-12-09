#![no_main]
use libfuzzer_sys::fuzz_target;
use tiny_jail::filters::{parse_and_expand_profile, OciSeccomp, ProfileError};

fuzz_target!(|profile: OciSeccomp| {
    let Ok(toml_str) = toml::to_string(&profile) else {
        return; // TOML serialization failed, not interesting
    };

    match parse_and_expand_profile(&toml_str) {
        Ok(_) => {} // Success is fine
        Err(e) => {
            // Only these errors are expected from valid TOML
            match e {
                ProfileError::UnknownSyscall(_) => {}
                ProfileError::UnknownGroup(_) => {}
                ProfileError::InvalidArgument(_) => {}
                ProfileError::LibSeccomp(_) => {}
                _ => panic!("Unexpected error from valid struct: {:?}", e),
            }
        }
    }
});
