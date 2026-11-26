//! Integration tests against `examples/vault`, run as a subprocess of the
//! real `soroban-testkit` binary — exercising the CLI the way a user
//! would, not just its internal functions.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

mod fixtures {
    pub const AUDIT_WITH_FINDINGS: &str = "examples/vault/src";
    pub const AUDIT_CLEAN_FILE: &str = "crates/cli/src/commands/mod.rs";
    pub const AUDIT_NESTED_FUNCTIONS: &str = "crates/cli/tests/fixtures/audit/nested_functions.rs";
    pub const VAULT_ROOT: &str = "examples/vault";
    pub const LIMITS_FUNCTION: &str = "batch_payout";
    pub const LIMITS_RAMP_PARAMETER: &str = "recipients";
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(args)
        .current_dir(workspace_root())
        .output()
        .expect("failed to run soroban-testkit")
}

fn run_cli_with_stdin(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(args)
        .current_dir(workspace_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run soroban-testkit");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(stdin.as_bytes())
        .expect("failed to write stdin");
    child
        .wait_with_output()
        .expect("failed to wait on soroban-testkit")
}

fn run_cli_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run soroban-testkit")
}

#[test]
fn no_subcommand_shows_concise_usage_and_exits_non_zero() {
    let output = run_cli(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("Usage:"), "{stderr}");
    assert!(stderr.contains("soroban-testkit"), "{stderr}");
    // Concise: a missing-subcommand error, not a panic or backtrace.
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(!stderr.contains("RUST_BACKTRACE"), "{stderr}");
}

#[test]
fn help_invocation_succeeds_and_lists_subcommands() {
    let output = run_cli(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("Usage:"), "{stdout}");
    assert!(stdout.contains("coverage"), "{stdout}");
    assert!(stdout.contains("limits"), "{stdout}");
    assert!(stdout.contains("audit"), "{stdout}");
}

#[test]
fn audit_reports_findings_against_vault() {
    let output = run_cli(&["audit", fixtures::AUDIT_WITH_FINDINGS]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
    assert!(stdout.contains("missing-ttl-bump"), "{stdout}");
    assert!(stdout.contains("unchecked-i128-arithmetic"), "{stdout}");
    assert!(stdout.contains("not a security product"), "{stdout}");
}

#[test]
fn audit_strict_exits_non_zero_on_findings() {
    let output = run_cli(&["audit", fixtures::AUDIT_WITH_FINDINGS, "--strict"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit finding(s)"), "{stderr}");
}

#[test]
fn audit_reports_no_findings_on_a_clean_directory() {
    let output = run_cli(&["audit", fixtures::AUDIT_CLEAN_FILE]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("no findings"), "{stdout}");
    assert!(
        stdout.contains("a missing finding is not a security guarantee"),
        "a clean run must still carry the disclaimer: {stdout}"
    );
}

#[test]
fn audit_reads_source_from_stdin_when_path_is_dash() {
    let src = r#"
        #[contractimpl]
        impl Token {
            pub fn transfer(to: Address, amount: i128) {
                let total = amount + 1;
            }
        }
    "#;
    let output = run_cli_with_stdin(&["audit", "-"], src);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
    assert!(stdout.contains("unchecked-i128-arithmetic"), "{stdout}");
    assert!(stdout.contains("<stdin>"), "{stdout}");
}

#[test]
fn audit_arithmetic_findings_report_the_operator_line() {
    let src = r#"
fn pay(
    amount: i128,
) {
    let first = amount
        + 1;
}
"#;
    let output = run_cli_with_stdin(&["audit", "-"], src);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("<stdin>:6: [warning] unchecked-i128-arithmetic"),
        "the operator is on line 6: {stdout}"
    );
}

#[test]
fn audit_stdin_reports_no_findings_on_empty_input() {
    let output = run_cli_with_stdin(&["audit", "-"], "");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("no findings"), "{stdout}");
}

#[test]
fn audit_stdin_reports_invalid_input_as_skipped() {
    let output = run_cli_with_stdin(&["audit", "-"], "fn {{{ not valid rust");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Still exit 0: an editor buffer may be mid-edit (#144).
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("no findings"), "{stdout}");
    assert!(
        stdout.contains("1 file could not be parsed and was not audited"),
        "{stdout}"
    );
    assert!(
        stderr.contains("warning: skipped <stdin>:1:"),
        "the skipped file is named with its parse position: {stderr}"
    );
}

#[test]
fn audit_json_declares_schema_version_and_findings() {
    let output = run_cli(&["audit", fixtures::AUDIT_WITH_FINDINGS, "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(
        stdout.starts_with("{\"schema_version\":1,"),
        "schema_version must lead the document: {stdout}"
    );
    assert!(stdout.contains("\"finding_count\":"), "{stdout}");
    assert!(
        stdout.contains("\"rule\":\"missing-require-auth\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"disclaimer\":\"soroban-testkit audit"),
        "{stdout}"
    );
}

#[test]
fn audit_json_on_a_clean_file_is_an_empty_findings_list() {
    let output = run_cli(&["audit", fixtures::AUDIT_CLEAN_FILE, "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(
        stdout
            .trim()
            .ends_with(",\"finding_count\":0,\"findings\":[]}"),
        "{stdout}"
    );
}

// ---- #215: isolated WASM artifacts for parallel test execution -----------

/// A uniquely-named temp dir for one integration test.
///
/// Each instance gets its own directory under the system temp dir so that
/// parallel tests never race on a shared `target/wasm32v1-none/release/*.wasm`.
/// The directory (and every generated artifact inside it) is removed when the
/// `IsolatedDir` is dropped, leaving no residue behind.
struct IsolatedDir {
    path: PathBuf,
}

impl Drop for IsolatedDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

static ISO_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Creates a fresh, uniquely-named temp dir for `test_name`.
fn isolated_dir(test_name: &str) -> io::Result<IsolatedDir> {
    let base = std::env::temp_dir();
    let id = ISO_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = base.join(format!(
        "soroban-testkit-integration-{test_name}-{}-{}",
        std::process::id(),
        id
    ));
    std::fs::create_dir_all(&path)?;
    Ok(IsolatedDir { path })
}

/// Builds the `vault` contract into `iso`'s private target dir and returns the
/// path to the generated `vault.wasm`. Because every caller passes its own
/// `IsolatedDir`, parallel tests never clobber each other's artifacts.
fn build_isolated_vault_wasm(iso: &IsolatedDir) -> PathBuf {
    let target_dir = iso.path.join("target");
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "vault",
            "--target",
            "wasm32v1-none",
            "--release",
            "--target-dir",
            target_dir.to_str().expect("target dir is valid unicode"),
        ])
        .current_dir(workspace_root())
        .status()
        .expect("failed to build vault.wasm");
    assert!(status.success(), "cargo build for vault must succeed");

    let wasm = target_dir
        .join("wasm32v1-none")
        .join("release")
        .join("vault.wasm");
    assert!(wasm.exists(), "expected vault.wasm at {wasm:?} after build");
    wasm
}

#[test]
fn limits_finds_the_real_mainnet_write_ceiling_for_batch_payout() {
    let iso = isolated_dir("limits-batch-payout").expect("isolated temp dir");
    let wasm = build_isolated_vault_wasm(&iso);
    let output = run_cli(&[
        "limits",
        "--contract",
        wasm.to_str().unwrap(),
        "--fn",
        fixtures::LIMITS_FUNCTION,
        "--ramp",
        fixtures::LIMITS_RAMP_PARAMETER,
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("last successful recipients"), "{stdout}");
    assert!(stdout.contains("instructions:"), "{stdout}");
    assert!(stdout.contains("memory bytes:"), "{stdout}");
}

#[test]
fn limits_reports_an_actionable_error_for_an_unknown_function() {
    let iso = isolated_dir("limits-unknown-fn").expect("isolated temp dir");
    let wasm = build_isolated_vault_wasm(&iso);
    let output = run_cli(&[
        "limits",
        "--contract",
        wasm.to_str().unwrap(),
        "--fn",
        "does_not_exist",
        "--ramp",
        "x",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("no function named"), "{stderr}");
}

#[test]
fn isolated_temp_dir_is_created_used_and_cleaned_up() {
    let wasm_path;
    {
        let iso = isolated_dir("cleanup-verification").expect("isolated temp dir");
        assert!(
            iso.path.is_dir(),
            "temp dir must exist while in scope: {:?}",
            iso.path
        );
        wasm_path = build_isolated_vault_wasm(&iso);
        assert!(
            wasm_path.exists(),
            "wasm must exist inside the temp dir: {wasm_path:?}"
        );
    }
    // `iso` was dropped above: the temp dir and every artifact in it must be gone.
    assert!(
        !wasm_path.exists(),
        "temp dir and its wasm must be removed after the test: {wasm_path:?}"
    );
    assert!(
        !wasm_path.parent().map(|p| p.exists()).unwrap_or(false),
        "temp dir itself must be removed after the test"
    );
}

#[test]
fn audit_paths_are_relative_to_the_audited_root_from_any_working_directory() {
    let root = workspace_root();
    let vault_src = root.join(fixtures::AUDIT_WITH_FINDINGS);
    let from_workspace = run_cli_in(&root, &["audit", fixtures::AUDIT_WITH_FINDINGS, "--json"]);
    let from_crate = run_cli_in(
        &root.join(fixtures::VAULT_ROOT),
        &["audit", "src", "--json"],
    );
    let absolute = run_cli_in(
        &root.join("crates"),
        &["audit", vault_src.to_str().unwrap(), "--json"],
    );

    let stdout = String::from_utf8_lossy(&from_workspace.stdout);
    assert!(stdout.contains("\"file\":\"lib.rs\""), "{stdout}");
    assert!(!stdout.contains("examples/vault"), "{stdout}");
    assert_eq!(from_workspace.stdout, from_crate.stdout);
    assert_eq!(from_workspace.stdout, absolute.stdout);
}

#[test]
fn audit_text_output_uses_root_relative_paths() {
    let output = run_cli_in(&workspace_root().join(fixtures::VAULT_ROOT), &["audit"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(
        stdout.lines().any(|l| l.starts_with("src/lib.rs:")),
        "{stdout}"
    );
    assert!(!stdout.contains("./"), "{stdout}");
}

#[test]
fn no_color_output_is_ansi_free() {
    for args in [
        &[
            "--no-color",
            "audit",
            fixtures::AUDIT_WITH_FINDINGS,
            "--strict",
        ][..],
        &[
            "audit",
            fixtures::AUDIT_WITH_FINDINGS,
            "--no-color",
            "--json",
        ][..],
        &["--no-color", "audit", "does/not/exist.rs", "--bogus"][..],
    ] {
        let output = run_cli(args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stdout.contains('\x1b'), "{args:?} stdout: {stdout}");
        assert!(!stderr.contains('\x1b'), "{args:?} stderr: {stderr}");
    }
}

#[test]
fn no_color_env_var_keeps_errors_ansi_free() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(["audit", fixtures::AUDIT_WITH_FINDINGS, "--strict"])
        .current_dir(workspace_root())
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run soroban-testkit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("error: "), "{stderr}");
    assert!(!stderr.contains('\x1b'), "{stderr}");
}

#[test]
fn quiet_drops_advisory_notes_but_keeps_findings() {
    let output = run_cli(&["-q", "audit", fixtures::AUDIT_WITH_FINDINGS]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
    assert!(!stdout.contains("not a security product"), "{stdout}");

    let clean = run_cli(&["audit", fixtures::AUDIT_CLEAN_FILE, "--quiet"]);
    assert!(clean.status.success());
    assert!(clean.stdout.is_empty(), "{:?}", clean.stdout);
}

#[test]
fn quiet_still_reports_errors_and_json() {
    let strict = run_cli(&[
        "--quiet",
        "audit",
        fixtures::AUDIT_WITH_FINDINGS,
        "--strict",
    ]);
    assert!(!strict.status.success());
    let stderr = String::from_utf8_lossy(&strict.stderr);
    assert!(stderr.contains("audit finding(s)"), "{stderr}");

    let json = run_cli(&["--quiet", "audit", fixtures::AUDIT_WITH_FINDINGS, "--json"]);
    let stdout = String::from_utf8_lossy(&json.stdout);
    assert!(stdout.starts_with("{\"schema_version\":1,"), "{stdout}");
}

#[test]
fn verbose_adds_diagnostics_on_stderr_only() {
    let normal = run_cli(&["audit", fixtures::AUDIT_WITH_FINDINGS]);
    let verbose = run_cli(&["--verbose", "audit", fixtures::AUDIT_WITH_FINDINGS]);
    let stderr = String::from_utf8_lossy(&verbose.stderr);

    assert!(verbose.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("scanning "), "{stderr}");
    assert!(stderr.contains("lib.rs"), "{stderr}");
    assert!(normal.stderr.is_empty());
    assert_eq!(normal.stdout, verbose.stdout);
}

#[test]
fn quiet_and_verbose_conflict() {
    let output = run_cli(&["-q", "-v", "audit", fixtures::AUDIT_WITH_FINDINGS]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
}

#[test]
fn coverage_help_includes_usage_examples() {
    let output = run_cli(&["coverage", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("EXAMPLES"), "{stdout}");
    assert!(stdout.contains("--format html"), "{stdout}");
    assert!(stdout.contains("--format lcov"), "{stdout}");
    assert!(stdout.contains("--format json"), "{stdout}");
    assert!(stdout.contains("--fail-under"), "{stdout}");
    assert!(stdout.contains("--dry-run"), "{stdout}");
}

#[test]
fn limits_help_includes_usage_examples() {
    let output = run_cli(&["limits", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("EXAMPLES"), "{stdout}");
    assert!(stdout.contains("--contract"), "{stdout}");
    assert!(stdout.contains("--fn"), "{stdout}");
    assert!(stdout.contains("--ramp"), "{stdout}");
    assert!(stdout.contains("--dry-run"), "{stdout}");
}

#[test]
fn audit_help_includes_usage_examples() {
    let output = run_cli(&["audit", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("EXAMPLES"), "{stdout}");
    assert!(stdout.contains("--strict"), "{stdout}");
    assert!(stdout.contains("--json"), "{stdout}");
}

// ---- #204: coverage argument construction without cargo-llvm-cov --------

/// Runs the binary with `PATH` pointing at a directory that does not
/// exist, so neither `cargo` nor `cargo-llvm-cov` can be found: anything
/// that passes here demonstrably needs no external tool.
fn run_without_tools(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(args)
        .current_dir(workspace_root())
        .env(
            "PATH",
            workspace_root().join("target/no-tools-on-this-path"),
        )
        .env_remove("NO_COLOR")
        .output()
        .expect("failed to run soroban-testkit")
}

fn dry_run(args: &[&str]) -> String {
    let output = run_without_tools(args);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{args:?}: stderr: {stderr}");
    assert!(stderr.is_empty(), "{args:?}: stderr: {stderr}");
    stdout
}

#[test]
fn coverage_dry_run_prints_the_forwarded_flags_without_cargo_llvm_cov() {
    let cases: &[(&[&str], &str)] = &[
        (&["coverage", "--dry-run"], "cargo llvm-cov test\n"),
        (
            &[
                "coverage",
                "--dry-run",
                "--format",
                "lcov",
                "--fail-under",
                "92.5",
            ],
            "cargo llvm-cov test --lcov --output-path lcov.info --fail-under-lines 92.5\n",
        ),
        (
            &["coverage", "--dry-run", "--format", "html", "--open"],
            "cargo llvm-cov test --html --open\n",
        ),
        (
            &["coverage", "--dry-run", "--open"],
            "cargo llvm-cov test --html --open\n",
        ),
        (
            &["-v", "coverage", "--dry-run", "--fail-under", "80"],
            "cargo llvm-cov test --fail-under-lines 80 --verbose\n",
        ),
        (
            &["--no-color", "-q", "coverage", "--dry-run"],
            "CARGO_TERM_COLOR=never NO_COLOR=1 cargo llvm-cov test --color never --quiet\n",
        ),
    ];
    for (args, expected) in cases {
        assert_eq!(dry_run(args), *expected, "{args:?}");
    }
}

#[test]
fn coverage_open_with_lcov_is_rejected_before_running_anything() {
    let output = run_without_tools(&["coverage", "--format", "lcov", "--open"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.starts_with("error: --open only applies to the HTML report"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn coverage_without_cargo_on_path_reports_how_to_install_it() {
    let output = run_without_tools(&["coverage", "--fail-under", "80"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    // Version gating (#194) checks `cargo llvm-cov --version` before
    // running, so without tools on PATH the failure surfaces from the
    // version check, not from spawning the run. Accept any of the
    // install-related errors, all of which name the fix.
    assert!(
        stderr.starts_with("error: failed to inspect cargo-llvm-cov version")
            || stderr.starts_with("error: cargo llvm-cov --version failed")
            || stderr.starts_with("error: failed to run `cargo llvm-cov`"),
        "{stderr}"
    );
    assert!(stderr.contains("cargo install cargo-llvm-cov"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

/// `(line, rule)` for each finding in an `audit --json` document, in order.
fn audit_json_findings(json: &str) -> Vec<(usize, String)> {
    json.split("{\"file\":")
        .skip(1)
        .map(|finding| {
            let field = |name: &str| {
                let start = finding
                    .find(&format!("\"{name}\":"))
                    .unwrap_or_else(|| panic!("no {name} in {finding}"))
                    + name.len()
                    + 3;
                finding[start..]
                    .split([',', '}'])
                    .next()
                    .unwrap()
                    .trim_matches('"')
                    .to_string()
            };
            (field("line").parse().unwrap(), field("rule"))
        })
        .collect()
}

/// The 1-based line of the fixture line containing `needle`.
fn fixture_line(path: &str, needle: &str) -> usize {
    let src = std::fs::read_to_string(workspace_root().join(path)).unwrap();
    src.lines()
        .position(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("{needle:?} not in {path}"))
        + 1
}

#[test]
fn audit_reports_each_nested_function_and_expression_exactly_once() {
    let fixture = fixtures::AUDIT_NESTED_FUNCTIONS;
    let output = run_cli(&["audit", fixture, "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");

    let line = |needle| fixture_line(fixture, needle);
    let mut actual = audit_json_findings(&stdout);
    actual.sort();
    let mut expected = vec![
        // `outer`: its nested helper's require_auth does not count for it
        (line("pub fn outer("), "missing-require-auth".to_string()),
        // `a + b + c` parses as `(a + b) + c` but is one expression
        (line("a + b + c"), "unchecked-i128-arithmetic".to_string()),
        // `helper`'s storage read and arithmetic, reported for `helper` only
        (line("fn helper("), "missing-ttl-bump".to_string()),
        (
            line("stored * 2i128"),
            "unchecked-i128-arithmetic".to_string(),
        ),
        // two separate expressions in `separate`
        (
            line("x + compute("),
            "unchecked-i128-arithmetic".to_string(),
        ),
        (line("y - 1i128,"), "unchecked-i128-arithmetic".to_string()),
    ];
    expected.sort();
    assert_eq!(actual, expected, "{stdout}");
    assert!(stdout.contains("\"finding_count\":6,"), "{stdout}");
}

#[test]
fn audit_rule_flag_runs_every_selected_rule_and_only_those() {
    let all = run_cli(&["audit", fixtures::AUDIT_WITH_FINDINGS, "--json"]);
    let all = audit_json_findings(&String::from_utf8_lossy(&all.stdout));
    let count = |findings: &[(usize, String)], rule: &str| {
        findings.iter().filter(|(_, r)| r == rule).count()
    };
    assert!(count(&all, "missing-require-auth") > 0);
    assert!(count(&all, "missing-ttl-bump") > 0);
    assert!(count(&all, "unchecked-i128-arithmetic") > 0);

    // Repeated and comma-separated forms select the same two rules; selecting
    // one rule never hides the findings of another selected rule.
    for args in [
        &[
            "--rule",
            "missing-require-auth",
            "--rule",
            "missing-ttl-bump",
        ][..],
        &["--rule", "missing-require-auth,missing-ttl-bump"][..],
    ] {
        let mut argv = vec!["audit", fixtures::AUDIT_WITH_FINDINGS, "--json"];
        argv.extend_from_slice(args);
        let output = run_cli(&argv);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{args:?}: {stdout}");
        assert!(stdout.starts_with("{\"schema_version\":1,"), "{stdout}");
        assert!(
            stdout.contains("\"rules\":[\"missing-require-auth\",\"missing-ttl-bump\"]"),
            "{stdout}"
        );
        let selected = audit_json_findings(&stdout);
        assert_eq!(
            count(&selected, "missing-require-auth"),
            count(&all, "missing-require-auth")
        );
        assert_eq!(
            count(&selected, "missing-ttl-bump"),
            count(&all, "missing-ttl-bump")
        );
        assert_eq!(count(&selected, "unchecked-i128-arithmetic"), 0);
    }
}

#[test]
fn audit_exclude_rule_skips_only_the_named_rules() {
    let output = run_cli(&[
        "audit",
        fixtures::AUDIT_WITH_FINDINGS,
        "--exclude-rule",
        "unchecked-i128-arithmetic",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
    assert!(stdout.contains("missing-ttl-bump"), "{stdout}");
    assert!(!stdout.contains("unchecked-i128-arithmetic"), "{stdout}");
    assert!(
        stdout.contains("audit: running only missing-require-auth, missing-ttl-bump"),
        "{stdout}"
    );
}

#[test]
fn audit_rule_selection_combines_with_strict() {
    // --strict counts only the findings of the rules that ran.
    // Excluding every rule leaves nothing to audit: a usage error, not a pass.
    let nothing = run_cli(&[
        "audit",
        fixtures::AUDIT_NESTED_FUNCTIONS,
        "--strict",
        "--exclude-rule",
        "missing-require-auth,unchecked-i128-arithmetic,missing-ttl-bump",
    ]);
    assert_eq!(
        nothing.status.code(),
        Some(2),
        "excluding every rule is a usage error"
    );

    let strict = run_cli(&[
        "audit",
        fixtures::AUDIT_NESTED_FUNCTIONS,
        "--strict",
        "--rule",
        "missing-ttl-bump",
    ]);
    let stderr = String::from_utf8_lossy(&strict.stderr);
    assert_eq!(strict.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("1 audit finding(s) (--strict)"), "{stderr}");
}

#[test]
fn audit_rule_selection_rejects_unknown_and_contradictory_rules_as_usage_errors() {
    for args in [
        &["--rule", "no-such-rule"][..],
        &["--exclude-rule", "no-such-rule"][..],
        &[
            "--rule",
            "missing-ttl-bump",
            "--exclude-rule",
            "missing-ttl-bump",
        ][..],
    ] {
        let mut argv = vec!["audit", fixtures::AUDIT_WITH_FINDINGS];
        argv.extend_from_slice(args);
        let output = run_cli(&argv);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.starts_with("error:"), "{stderr}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

// ---- #142 / #144: audit path filters and parse-error reporting ----------

/// A temp crate tree for audit tests: `src/lib.rs` (one entry-point finding),
/// `src/generated/bindings.rs` (one finding), `vendor/dep/lib.rs` (one
/// finding) and `src/broken.rs` (not valid Rust).
fn audit_tree(test_name: &str) -> IsolatedDir {
    let iso = isolated_dir(test_name).expect("temp dir");
    let finding = |name: &str| {
        format!("#[contractimpl]\nimpl C {{\n    pub fn {name}(to: Address) {{}}\n}}\n")
    };
    for (path, body) in [
        ("src/lib.rs", finding("lib_entry")),
        ("src/generated/bindings.rs", finding("generated_entry")),
        ("vendor/dep/lib.rs", finding("vendored_entry")),
        ("src/broken.rs", "pub fn broken( {\n".to_string()),
    ] {
        let file = iso.path.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, body).unwrap();
    }
    iso
}

fn audit_tree_json(iso: &IsolatedDir, extra: &[&str]) -> (Output, String) {
    let root = iso.path.to_str().unwrap().to_string();
    let mut args = vec!["audit", root.as_str(), "--json"];
    args.extend_from_slice(extra);
    let output = run_cli(&args);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (output, stdout)
}

#[test]
fn audit_exclude_skips_generated_and_vendored_directories() {
    let iso = audit_tree("audit_exclude");
    let (output, all) = audit_tree_json(&iso, &[]);
    assert!(output.status.success(), "{all}");
    for name in ["lib_entry", "generated_entry", "vendored_entry"] {
        assert!(all.contains(name), "{name} missing without filters: {all}");
    }

    let (output, filtered) =
        audit_tree_json(&iso, &["--exclude", "generated", "--exclude", "vendor/**"]);
    assert!(output.status.success(), "{filtered}");
    assert!(filtered.contains("lib_entry"), "{filtered}");
    assert!(!filtered.contains("generated_entry"), "{filtered}");
    assert!(!filtered.contains("vendored_entry"), "{filtered}");
    assert!(filtered.contains("\"finding_count\":1,"), "{filtered}");
}

#[test]
fn audit_include_limits_the_audit_to_matching_paths() {
    let iso = audit_tree("audit_include");
    let (output, stdout) = audit_tree_json(&iso, &["--include", "vendor"]);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("vendored_entry"), "{stdout}");
    assert!(stdout.contains("\"finding_count\":1,"), "{stdout}");
    // src/broken.rs was not selected, so it is neither audited nor skipped.
    assert!(stdout.contains("\"skipped\":[]"), "{stdout}");
}

#[test]
fn audit_filters_that_match_no_file_are_an_error() {
    let iso = audit_tree("audit_no_match");
    let (output, _) = audit_tree_json(&iso, &["--include", "contracts/**"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("matches --include/--exclude (4 filtered out)"),
        "{stderr}"
    );
}

#[test]
fn audit_filters_are_a_usage_error_with_stdin() {
    let output = run_cli_with_stdin(&["audit", "-", "--exclude", "target"], "fn ok() {}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("cannot be used when reading from stdin"),
        "{stderr}"
    );
}

#[test]
fn audit_reports_unparseable_files_with_path_and_parser_error() {
    let iso = audit_tree("audit_parse_errors");
    let root = iso.path.to_str().unwrap();

    let text = run_cli(&["audit", root]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    let stderr = String::from_utf8_lossy(&text.stderr);
    assert!(text.status.success(), "{stderr}");
    assert!(
        stderr.contains("warning: skipped src/broken.rs:1:"),
        "{stderr}"
    );
    assert!(
        stderr.contains("not valid Rust, so it was not audited"),
        "{stderr}"
    );
    assert!(
        stdout.contains("1 file could not be parsed and was not audited"),
        "{stdout}"
    );

    let (_, json) = audit_tree_json(&iso, &[]);
    assert!(
        json.contains("\"skipped\":[{\"file\":\"src/broken.rs\",\"line\":1,\"column\":"),
        "{json}"
    );
    // stdout stays one JSON document; the warning is not printed with --json.
    let json_run = run_cli(&["audit", root, "--json"]);
    assert!(
        !String::from_utf8_lossy(&json_run.stderr).contains("warning: skipped"),
        "--json keeps skipped files in the document only"
    );

    // Excluding the broken file silences it.
    let (_, excluded) = audit_tree_json(&iso, &["--exclude", "broken.rs"]);
    assert!(excluded.contains("\"skipped\":[]"), "{excluded}");
}

#[test]
fn audit_auth_findings_cover_entry_points_but_not_helpers() {
    let src = r#"
#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, to: Address) {}
}

fn send_to(env: &Env, to: &Address) {}

impl Vault {
    pub fn internal(to: Address) {}
}
"#;
    let output = run_cli_with_stdin(&["audit", "-", "--json"], src);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(
        audit_json_findings(&stdout),
        vec![(4, "missing-require-auth".to_string())],
        "{stdout}"
    );
}

#[test]
fn audit_qualified_and_aliased_address_fixture() {
    let output = run_cli(&[
        "audit",
        "crates/cli/tests/fixtures/audit/qualified_address.rs",
        "--json",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(
        audit_json_findings(&stdout),
        vec![
            (13, "missing-require-auth".to_string()),
            (14, "missing-require-auth".to_string()),
            (15, "missing-require-auth".to_string()),
            (16, "missing-require-auth".to_string()),
            (17, "missing-require-auth".to_string()),
            (18, "missing-require-auth".to_string()),
        ],
        "{stdout}"
    );
}
