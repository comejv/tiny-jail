# Fuzzing Notes

## Overview
Fuzzing is performed using `cargo-fuzz` (libFuzzer) to test the robustness of the `tiny-jail` profile parsing and application logic.

## Targets
- `fuzz_apply`: Generates valid `OciSeccomp` profiles using `arbitrary` and applies them using `apply_profile`. This exercises the core logic of converting OCI profiles to libseccomp filters.
- `fuzz_structured`: Generates `OciSeccomp` profiles and tests `parse_and_expand_profile`, focusing on abstract syscall expansion and profile validation.

## Findings & Fixes

### 1. `fuzz_structured` Panic
- **Issue:** The fuzzer generated profiles with empty abstract group names (`""`), causing a panic in `parse_and_expand_profile` due to an unhandled `ProfileError::UnknownGroup`.
- **Fix:** Updated `fuzz_structured.rs` to gracefully handle `ProfileError::UnknownGroup`, treating it as a valid rejection rather than a crash.

### 2. Memory Leak in `fuzz_apply`
- **Issue:** A memory leak was detected in `libseccomp` when attempting to add a rule with a condition on an argument index out of bounds for the specific syscall (e.g., index 4 for `faccessat`, which has arity 4/indices 0-3).
- **Fix:** Implemented `get_syscall_arity` in `src/filters.rs` and added validation in `apply_syscall_rule`. Conditions with invalid argument indices are now logged as warnings and skipped, preventing the leak.

### 3. Timeout in `fuzz_apply`
- **Issue:** The fuzzer was timing out after 20 seconds, likely due to the large number of syscalls in the profile. Timeout happened deep into the libseccomp library: add_rule_conditional->seccomp_rule_add_array->db_col_rule_add->arch_filter_rule_add->[...]->_db_tree_put

## Commands
Run fuzzers from the `tiny-jail` directory:

```bash
# Run fuzz_apply
cargo fuzz run fuzz_apply -- -max_len=10000 -timeout=10 -detect_leaks=0

# Run fuzz_structured
cargo fuzz run fuzz_structured -- -max_len=10000 -timeout=10 -detect_leaks=0
```
