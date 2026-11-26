//! Regression coverage for the isolated limits probe process.
use super::*;

#[test]
fn bounds_distinguish_cap_from_a_measured_failure() {
    assert_eq!(boundary_kind(None), "search_cap_reached");
    assert_eq!(boundary_kind(Some(8)), "measured_failure");
    let result = find_ladder_bounds(4, SEARCH_CEILING, |values: &[u32]| {
        Ok(Some(values.iter().map(|_| true).collect()))
    })
    .unwrap();
    assert_eq!(result, Search::Done((Some(SEARCH_CEILING), None)));
}

#[test]
fn json_reports_the_boundary_without_removing_legacy_fields() {
    let args = LimitsArgs {
        contract: "fixture.wasm".into(),
        function: "run".into(),
        ramp: "amount".into(),
        start: 0,
        step: 1,
        jobs: 1,
        probe_timeout: 120,
        repeat: 1,
        dry_run: false,
        bool_defaults: Vec::new(),
        auth_mode: AuthMode::All,
        json: true,
    };
    let cost = Measured {
        instructions: Spread::of(vec![100]),
        memory_bytes: Spread::of(vec![200]),
    };
    let capped: serde_json::Value = serde_json::from_str(&render_json(
        &args,
        7,
        &cost,
        None,
        None,
        i64::from(SEARCH_CEILING),
        None,
    ))
    .unwrap();
    assert_eq!(capped["schema_version"], 1);
    assert_eq!(capped["last_successful"], 7);
    assert_eq!(capped["boundary"]["kind"], "search_cap_reached");
    assert_eq!(capped["boundary"]["search_ceiling"], SEARCH_CEILING);
    assert!(capped["boundary"]["first_failing"].is_null());

    let measured: serde_json::Value = serde_json::from_str(&render_json(
        &args,
        7,
        &cost,
        Some(8),
        Some("contract_rejected"),
        i64::from(SEARCH_CEILING),
        None,
    ))
    .unwrap();
    assert_eq!(measured["boundary"]["kind"], "measured_failure");
    assert_eq!(measured["boundary"]["first_failing"], 8);
    assert_eq!(measured["boundary"]["failure_outcome"], "contract_rejected");
}

#[test]
fn json_reports_repeat_spread_and_generated_items_for_vec_ramps() {
    let args = LimitsArgs {
        contract: "fixture.wasm".into(),
        function: "batch_payout".into(),
        ramp: "recipients".into(),
        start: 0,
        step: 1,
        jobs: 1,
        probe_timeout: 120,
        repeat: 3,
        dry_run: false,
        bool_defaults: Vec::new(),
        auth_mode: AuthMode::All,
        json: true,
    };
    let cost = Measured {
        instructions: Spread::of(vec![30, 10, 20]),
        memory_bytes: Spread::of(vec![5, 7, 6]),
    };
    let doc: serde_json::Value = serde_json::from_str(&render_json(
        &args,
        512,
        &cost,
        None,
        None,
        i64::from(MAX_VEC_RAMP_ITEMS),
        Some(512),
    ))
    .unwrap();
    assert_eq!(doc["generated_items"], 512);
    assert_eq!(doc["instructions"], 20, "top-level figure is the median");
    assert_eq!(doc["memory_bytes"], 6);
    assert_eq!(doc["measurements"]["repeats"], 3);
    assert_eq!(doc["measurements"]["instructions"]["min"], 10);
    assert_eq!(doc["measurements"]["instructions"]["max"], 30);
    assert_eq!(doc["measurements"]["memory_bytes"]["median"], 6);
    assert_eq!(doc["boundary"]["search_ceiling"], MAX_VEC_RAMP_ITEMS);

    // An integer ramp has no item count.
    let integer = LimitsArgs {
        ramp: "amount".into(),
        function: "run".into(),
        ..args
    };
    let doc: serde_json::Value = serde_json::from_str(&render_json(
        &integer,
        7,
        &cost,
        None,
        None,
        i64::from(SEARCH_CEILING),
        None,
    ))
    .unwrap();
    assert!(doc["generated_items"].is_null());
}

#[test]
fn zero_timeout_is_rejected_before_accessing_a_contract() {
    let args = LimitsArgs {
        contract: "missing.wasm".into(),
        function: "run".into(),
        ramp: "amount".into(),
        start: 0,
        step: 1,
        jobs: 1,
        probe_timeout: 0,
        repeat: 1,
        dry_run: false,
        bool_defaults: Vec::new(),
        auth_mode: AuthMode::All,
        json: false,
    };
    let output = super::super::output::Output {
        verbosity: super::super::output::Verbosity::Quiet,
        color: false,
    };
    let error = run(args, output).unwrap_err();
    assert!(error.0.contains("--probe-timeout must be at least 1"));
}

#[cfg(unix)]
fn executable_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// Runs a probe against a script that was just written by `executable_script`,
/// retrying only when the launch fails with `ETXTBSY` ("Text file busy").
///
/// Tests run on parallel threads. If another test forks a child while this
/// script's file is still open for writing, the child briefly inherits that
/// write descriptor and the kernel refuses to execute the script until it
/// closes. The window is tiny, so a short retry is enough. Production probes
/// always run the CLI's own, already-built binary and never see this race.
#[cfg(unix)]
fn run_script_probe(
    executable: &Path,
    scratch: &ProbeScratch,
    args: &LimitsArgs,
    value: i64,
    timeout: Duration,
    verbose: bool,
) -> ProbeResult {
    const ETXTBSY_RETRIES: usize = 50;
    for _ in 0..ETXTBSY_RETRIES {
        let result = run_probe_process(
            executable,
            scratch,
            Path::new("fixture.wasm"),
            args,
            value,
            timeout,
            verbose,
        );
        match &result.outcome {
            ProbeExit::LaunchFailed(message) if message.contains("os error 26") => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => return result,
        }
    }
    run_probe_process(
        executable,
        scratch,
        Path::new("fixture.wasm"),
        args,
        value,
        timeout,
        verbose,
    )
}

#[cfg(unix)]
fn fixture_args() -> LimitsArgs {
    LimitsArgs {
        contract: "fixture.wasm".into(),
        function: "run".into(),
        ramp: "amount".into(),
        start: 0,
        step: 1,
        jobs: 1,
        probe_timeout: 120,
        repeat: 1,
        dry_run: false,
        bool_defaults: Vec::new(),
        auth_mode: AuthMode::All,
        json: false,
    }
}

#[cfg(unix)]
#[test]
fn subprocess_exit_classification_and_verbose_output() {
    let temp = ProbeScratch::create().unwrap();
    let args = fixture_args();
    for (name, shell, expected) in [
        ("success", "exit 0", ProbeExit::Success),
        (
            "rejection",
            "echo contract-rejected >&2; exit 10",
            ProbeExit::ContractRejected,
        ),
        ("abort", "exit 134", ProbeExit::HostAborted),
        (
            "setup",
            "echo invalid-setup >&2; exit 1",
            ProbeExit::LaunchFailed("probe setup failed; inspect --verbose diagnostics".into()),
        ),
    ] {
        let executable = executable_script(temp.path(), name, shell);
        let verbose = run_script_probe(&executable, &temp, &args, 17, Duration::from_secs(5), true);
        assert_eq!(verbose.outcome, expected, "{name}");
        if name == "rejection" {
            assert!(verbose.diagnostic.unwrap().contains("contract-rejected"));
            let quiet =
                run_script_probe(&executable, &temp, &args, 17, Duration::from_secs(5), false);
            assert!(quiet.diagnostic.is_none());
        }
    }
    let missing = run_probe_process(
        &temp.path().join("missing"),
        &temp,
        Path::new("fixture.wasm"),
        &args,
        17,
        Duration::from_secs(5),
        false,
    );
    assert!(matches!(missing.outcome, ProbeExit::LaunchFailed(_)));
}

#[cfg(unix)]
#[test]
fn hung_subprocess_times_out_and_is_reaped() {
    let temp = ProbeScratch::create().unwrap();
    let executable = executable_script(temp.path(), "hang", "while :; do :; done");
    let start = Instant::now();
    let result = run_script_probe(
        &executable,
        &temp,
        &fixture_args(),
        19,
        Duration::from_millis(75),
        true,
    );
    assert_eq!(result.outcome, ProbeExit::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn verbose_diagnostics_are_bounded() {
    let temp = ProbeScratch::create().unwrap();
    let executable = executable_script(
        temp.path(),
        "noisy",
        "i=0; while [ \"$i\" -lt 3000 ]; do echo 'diagnostic line' >&2; i=$((i + 1)); done; exit 10",
    );
    let result = run_script_probe(
        &executable,
        &temp,
        &fixture_args(),
        3,
        Duration::from_secs(5),
        true,
    );
    assert_eq!(result.outcome, ProbeExit::ContractRejected);
    let stderr = result.diagnostic.unwrap();
    assert!(stderr.len() < MAX_PROBE_STDERR_BYTES + 100);
    assert!(stderr.contains("child stderr truncated at 8192 bytes"));
}
