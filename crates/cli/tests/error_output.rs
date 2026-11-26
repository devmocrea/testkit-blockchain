//! Error output consistency (#202): every subcommand reports a failure as
//! exit status 1 plus a single `error: <message>` line on stderr, with no
//! Rust debug output, panic, or backtrace. The one documented exception is
//! `audit` invalid input, which exits 2. See the conventions on `CliError`
//! in `src/commands/mod.rs`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(args)
        .current_dir(workspace_root())
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run soroban-testkit")
}

/// Runs the CLI with `source` written to its stdin.
fn run_with_stdin(args: &[&str], source: &str) -> Output {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(args)
        .current_dir(workspace_root())
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run soroban-testkit");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    child
        .wait_with_output()
        .expect("failed to wait for soroban-testkit")
}

/// Shapes of raw `Debug` output that must never reach the user.
const DEBUG_MARKERS: &[&str] = &[
    "Os {",
    "kind:",
    " { ",
    "ScSpecType",
    "Box(",
    "\\\"",
    "panicked",
    "RUST_BACKTRACE",
];

/// Asserts `output` is a command failure in the shared format and returns
/// its message (the stderr text after `error: `).
fn assert_cli_error(output: &Output) -> String {
    assert_cli_error_with_code(output, 1)
}

/// [`assert_cli_error`] for a failure with a documented exit status other
/// than 1.
fn assert_cli_error_with_code(output: &Output, code: i32) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(output.status.code(), Some(code), "stderr: {stderr}");
    assert!(stderr.starts_with("error: "), "{stderr}");
    assert!(stderr.ends_with('\n'), "{stderr:?}");
    assert_eq!(stderr.matches("error:").count(), 1, "{stderr}");
    assert!(!stderr.contains('\x1b'), "{stderr}");
    for marker in DEBUG_MARKERS {
        assert!(
            !stderr.contains(marker),
            "debug output {marker:?} in: {stderr}"
        );
    }
    stderr["error: ".len()..].trim_end().to_string()
}

#[test]
fn audit_of_a_missing_path_fails_instead_of_reporting_no_findings() {
    let output = run(&["audit", "does/not/exist"]);
    let message = assert_cli_error_with_code(&output, 2);
    assert!(
        message.starts_with("cannot audit `does/not/exist`: "),
        "{message}"
    );
    assert!(
        message.contains("pass a contract crate's source directory"),
        "{message}"
    );
    assert!(
        output.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn audit_of_an_unreadable_directory_fails_instead_of_skipping_it() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "testkit-audit-unreadable-{}-{stamp}",
        std::process::id()
    ));
    let hidden = root.join("hidden");
    std::fs::create_dir_all(&hidden).expect("create temp audit tree");
    std::fs::write(hidden.join("lib.rs"), "fn ok() {}").expect("write temp source");
    let original = std::fs::metadata(&hidden)
        .expect("stat temp directory")
        .permissions();
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000))
        .expect("remove temp directory read permission");

    let inaccessible = std::fs::read_dir(&hidden).is_err();
    let output =
        inaccessible.then(|| run(&["audit", root.to_str().expect("temp path is valid UTF-8")]));

    std::fs::set_permissions(&hidden, original).expect("restore temp directory permissions");
    std::fs::remove_dir_all(&root).expect("remove temp audit tree");

    let Some(output) = output else {
        return;
    };
    let message = assert_cli_error(&output);
    assert!(
        message.starts_with(&format!("cannot audit `{}`", hidden.display())),
        "{message}"
    );
    assert!(
        message.contains("Permission denied") || message.contains("permission denied"),
        "{message}"
    );
}

#[test]
fn audit_strict_with_an_unparsable_source_exits_2_as_invalid_input() {
    let output = run_with_stdin(&["audit", "-", "--strict"], "pub fn {{{{{");
    let message = assert_cli_error_with_code(&output, 2);
    assert_eq!(
        message,
        "1 file(s) failed to parse and were not audited (--strict): <stdin>"
    );
}

#[test]
fn audit_of_an_unparsable_source_is_a_warning_without_strict() {
    let output = run_with_stdin(&["audit", "-"], "pub fn {{{{{");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("warning: skipped <stdin>: it failed to parse"),
        "{stderr}"
    );
}

#[test]
fn negative_start_and_step_parse_as_values_not_flags() {
    // A flag clap does not know exits 2 as a usage error. A parsed value gets
    // past argument parsing and fails when the missing contract is loaded.
    let output = run(&[
        "limits",
        "--contract",
        "missing.wasm",
        "--fn",
        "batch_payout",
        "--ramp",
        "recipients",
        "--start",
        "-5",
        "--step",
        "-2",
    ]);
    let message = assert_cli_error(&output);
    assert!(
        message.starts_with("failed to read `missing.wasm`: "),
        "{message}"
    );
}

#[test]
fn audit_strict_findings_use_the_shared_format() {
    let output = run(&["audit", "examples/vault/src", "--strict"]);
    let message = assert_cli_error(&output);
    assert!(
        message.ends_with("audit finding(s) (--strict)"),
        "{message}"
    );
}

#[test]
fn limits_with_a_missing_contract_names_the_path_and_the_fix() {
    let output = run(&[
        "limits",
        "--contract",
        "missing.wasm",
        "--fn",
        "batch_payout",
        "--ramp",
        "recipients",
    ]);
    let message = assert_cli_error(&output);
    assert!(
        message.starts_with("failed to read `missing.wasm`: "),
        "{message}"
    );
    assert!(message.contains("compiled contract .wasm"), "{message}");
    assert!(
        output.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn limits_with_a_non_wasm_file_explains_what_to_pass() {
    let output = run(&[
        "limits",
        "--contract",
        "README.md",
        "--fn",
        "batch_payout",
        "--ramp",
        "recipients",
    ]);
    let message = assert_cli_error(&output);
    assert!(
        message.starts_with("`README.md` is not a valid WebAssembly module"),
        "{message}"
    );
    assert!(message.contains("wasm32v1-none"), "{message}");
}

#[test]
fn limits_with_an_unknown_ramp_parameter_lists_the_real_ones() {
    let wasm = workspace_root().join("target/wasm32v1-none/release/vault.wasm");
    if !wasm.exists() {
        // Built by integration.rs's batch_payout limits test; skip if tests
        // ran in isolation without it.
        return;
    }
    let output = run(&[
        "limits",
        "--contract",
        wasm.to_str().unwrap(),
        "--fn",
        "batch_payout",
        "--ramp",
        "nonexistent_param",
    ]);
    let message = assert_cli_error(&output);
    assert!(
        message.starts_with("`batch_payout` has no parameter named `nonexistent_param`"),
        "{message}"
    );
    assert!(
        message.ends_with("; its parameters are `recipients`, `amount`"),
        "{message}"
    );
}

#[test]
fn usage_errors_also_start_with_the_error_prefix() {
    for args in [
        &["audit", "--bogus"][..],
        &["limits", "--contract", "x.wasm"][..],
    ] {
        let output = run(args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{args:?}");
        assert!(stderr.starts_with("error: "), "{args:?}: {stderr}");
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
    }
}
