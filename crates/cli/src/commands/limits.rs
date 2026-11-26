use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::panic;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use clap::{Args, ValueEnum};
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::token::StellarAssetClient;
use soroban_sdk::xdr::{ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef};
use soroban_sdk::{Address, Env, IntoVal, Symbol, Val, Vec as SVec};

use super::output::Output;
use super::{quote, CliError};

/// The signal handler only sets an atomic flag; no IO runs inside it.
static CANCELLED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
mod signals {
    use super::{Ordering, CANCELLED};
    use std::os::raw::c_int;
    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;
    unsafe extern "C" {
        fn signal(signum: c_int, handler: usize) -> usize;
    }
    extern "C" fn cancel(_: c_int) {
        CANCELLED.store(true, Ordering::Relaxed);
    }
    pub struct SignalGuard {
        previous_int: usize,
        previous_term: usize,
    }
    impl SignalGuard {
        pub fn install() -> Self {
            CANCELLED.store(false, Ordering::Relaxed);
            // SAFETY: The installed handler only writes an atomic flag.
            let previous_int = unsafe { signal(SIGINT, cancel as *const () as usize) };
            let previous_term = unsafe { signal(SIGTERM, cancel as *const () as usize) };
            Self {
                previous_int,
                previous_term,
            }
        }
    }
    impl Drop for SignalGuard {
        fn drop(&mut self) {
            // SAFETY: Restore the handlers returned by signal().
            unsafe {
                signal(SIGINT, self.previous_int);
                signal(SIGTERM, self.previous_term);
            }
        }
    }
}

#[cfg(not(unix))]
mod signals {
    pub struct SignalGuard;
    impl SignalGuard {
        pub fn install() -> Self {
            Self
        }
    }
}

/// Arguments for `soroban-testkit limits`.
#[derive(Args)]
#[command(after_help = "EXAMPLES:\n    \
    soroban-testkit limits --contract target/wasm32v1-none/release/my_contract.wasm --fn batch_payout --ramp recipients\n    \
    soroban-testkit limits --contract my_contract.wasm --fn transfer --ramp amount\n    \
    soroban-testkit limits --contract my_contract.wasm --fn transfer --ramp amount --bool-default paused=true --repeat 5")]
pub struct LimitsArgs {
    /// Path to the compiled contract .wasm file
    /// (e.g. `target/wasm32v1-none/release/<crate>.wasm`)
    #[arg(long, value_name = "PATH", verbatim_doc_comment)]
    contract: std::path::PathBuf,
    /// The contract function to ramp, as named in the contract's spec.
    #[arg(long = "fn", value_name = "NAME")]
    function: String,
    /// The parameter of --fn to increase on each attempt: an integer type
    /// (ramped as the value) or `Vec<T>` (ramped as its length)
    #[arg(long, value_name = "PARAM", verbatim_doc_comment)]
    ramp: String,
    /// First ramp value to probe (default 0), within the ramp parameter's type range
    #[arg(
        long,
        value_name = "N",
        default_value_t = 0,
        allow_negative_numbers = true
    )]
    start: i64,
    /// Step between ramp values (default 1; negative probes downwards). Probes are start + k*step for k = 0, 1, 2, 4, ...
    #[arg(
        long,
        value_name = "N",
        default_value_t = 1,
        allow_negative_numbers = true
    )]
    step: i64,
    // Results are read back in ramp order, so the boundary matches a sequential
    // run. Probes past the first failure are discarded; see BUILD_SPEC.md.
    /// Probe up to N ramp values at once (1 to 8, default 1).
    #[arg(long, value_name = "N", default_value_t = 1)]
    jobs: usize,
    /// Stop an individual probe after N seconds (default 120; minimum 1).
    #[arg(long, value_name = "SECONDS", default_value_t = 120)]
    probe_timeout: u64,
    /// Measure the final value N times (1 to 16, default 1). With N above 1, the report gives the median with the min and max.
    #[arg(long, value_name = "N", default_value_t = 1)]
    repeat: usize,
    /// Generate and print one probe's arguments without invoking the contract.
    /// This validates the contract spec and is useful when diagnosing defaults.
    #[arg(long)]
    dry_run: bool,
    /// Override a non-ramp bool parameter's default (repeatable): --bool-default enabled=true.
    #[arg(long = "bool-default", value_name = "PARAM=BOOL", action = clap::ArgAction::Append)]
    bool_defaults: Vec<String>,
    /// Authorization mock scope: all (default), root-only, or none.
    #[arg(long = "auth-mode", value_enum, default_value = "all")]
    auth_mode: AuthMode,
    /// Print the result as a JSON document (`schema_version` 1) on stdout.
    #[arg(long)]
    json: bool,
}

/// Authorization behavior for each isolated limits probe.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum AuthMode {
    /// Approve every authorization entry, including nested invocations.
    #[default]
    All,
    /// Approve only authorization required by the root invocation.
    RootOnly,
    /// Do not install authorization mocks.
    None,
}

impl AuthMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::RootOnly => "root-only",
            Self::None => "none",
        }
    }
}

/// Largest accepted `--repeat`. Each repeat is one more in-process measurement.
pub const MAX_REPEATS: usize = 16;

/// Largest accepted `--jobs`. Each concurrent probe is a full child process.
pub const MAX_JOBS: usize = 8;

/// Largest ramp value tried while doubling. Values above it are never probed.
const SEARCH_CEILING: u32 = 1 << 24;

/// Largest number of items a `Vec` ramp generates for one probe. The search for
/// a `Vec` parameter stops here, so no probe allocates more items than this.
const MAX_VEC_RAMP_ITEMS: u32 = 1024;

const MAX_PROBE_STDERR_BYTES: usize = 8 * 1024;
pub const PROBE_REJECTED_EXIT_CODE: i32 = 10;

/// Version of the `limits --json` document shape. Bump it on any breaking change.
const LIMITS_JSON_SCHEMA_VERSION: u32 = 1;

/// The spec entry a contract uses for its constructor. It runs at deployment,
/// so it is never a ramp target.
const CONSTRUCTOR_NAME: &str = "__constructor";
/// When enabled, probing starts at 0 and includes monotonicity sampling (issue #186, #187).
const ENABLE_ZERO_PROBE: bool = true;
const ENABLE_MONOTONICITY_CHECK: bool = true;

/// Outcome of one search phase. `Cancelled` carries the best known success.
#[derive(Debug, PartialEq)]
enum Search<T> {
    Done(T),
    Cancelled { last_ok: Option<u32> },
}

/// Protocol for isolated child probes: a normal rejection is not a host abort.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ProbeExit {
    Success,
    ContractRejected,
    HostAborted,
    TimedOut,
    LaunchFailed(String),
    Cancelled,
}

impl ProbeExit {
    fn label(&self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::ContractRejected => "contract_rejected",
            Self::HostAborted => "host_aborted",
            Self::TimedOut => "timed_out",
            Self::LaunchFailed(_) => "launch_failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug)]
struct ProbeResult {
    outcome: ProbeExit,
    diagnostic: Option<String>,
}

fn classify_probe_exit(status: ExitStatus) -> ProbeExit {
    match status.code() {
        Some(0) => ProbeExit::Success,
        Some(PROBE_REJECTED_EXIT_CODE) => ProbeExit::ContractRejected,
        Some(1) => {
            ProbeExit::LaunchFailed("probe setup failed; inspect --verbose diagnostics".into())
        }
        _ => ProbeExit::HostAborted,
    }
}

fn boundary_kind(first_failing: Option<i64>) -> &'static str {
    if first_failing.is_some() {
        "measured_failure"
    } else {
        "search_cap_reached"
    }
}

/// Hidden: runs exactly one probe (a single ramp value) and reports its
/// outcome via exit code. See [`run`]'s doc comment for why this exists
/// as a separate process rather than an in-process call.
#[derive(Args)]
pub struct ProbeArgs {
    #[arg(long)]
    contract: std::path::PathBuf,
    #[arg(long = "fn")]
    function: String,
    #[arg(long)]
    ramp: String,
    #[arg(long, allow_negative_numbers = true)]
    value: i64,
    #[arg(long = "bool-default", value_name = "PARAM=BOOL", action = clap::ArgAction::Append)]
    bool_defaults: Vec<String>,
    #[arg(long = "auth-mode", value_enum, default_value = "all")]
    auth_mode: AuthMode,
}

/// Empirically discovers a resource ceiling by invoking `--fn` with an
/// increasing `--ramp` parameter — natively, with no network access —
/// until it fails, then reports the last successful value plus the CPU
/// instructions and memory consumed at that point.
///
/// # Why this spawns a subprocess per attempt
///
/// Ramping deliberately drives a real, compiled `.wasm` contract past its
/// resource limits. Verified empirically: when that failure happens
/// *during actual WASM execution* (as opposed to a native, non-WASM
/// `#[contract]` registration), the host can abort the whole process
/// (`thread caused non-unwinding panic. aborting.`) rather than return an
/// error or unwind — neither `catch_unwind` nor `try_invoke_contract`
/// (the SDK's own no-panic call path) prevents this for the WASM target.
/// So each attempt runs in its own child process (`soroban-testkit
/// __limits-probe`, hidden from `--help`): if that child aborts, only the
/// child dies, and the exit code alone tells this command whether that
/// ramp value succeeded.
///
/// # Scope
///
/// The ramp parameter must be a numeric type (`u32`/`i32`/`u64`/`i64`/
/// `u128`/`i128`, ramped as the value itself) or `Vec<Address>` (ramped as
/// the number of generated addresses) — this covers the common "maximum
/// recipients in a batch operation" question directly. Every other
/// parameter is filled with a fixed default (an address, `0`, an empty
/// collection, ...). A parameter type this command doesn't know how to
/// default (`Map`, `Tuple`, `Option`, `Result`, a user-defined type, ...)
/// is reported as an error rather than guessed at.
///
/// Ledger read/write counts and transaction size are **not** reported:
/// they come from a transaction's simulated resource footprint, which
/// this command's native invocation does not produce (that requires the
/// network-dependent `stellar contract invoke` simulation path, which
/// this crate deliberately avoids — see its "zero network access"
/// constraint). Only CPU instructions and memory, available locally via
/// the host's budget, are reported.
pub fn run(args: LimitsArgs, out: Output) -> Result<(), CliError> {
    if args.jobs == 0 || args.jobs > MAX_JOBS {
        return Err(CliError(format!(
            "--jobs must be between 1 and {MAX_JOBS} (got {})",
            args.jobs
        )));
    }
    if args.probe_timeout == 0 {
        return Err(CliError(
            "--probe-timeout must be at least 1 second".to_string(),
        ));
    }
    if args.repeat == 0 || args.repeat > MAX_REPEATS {
        return Err(CliError(format!(
            "--repeat must be between 1 and {MAX_REPEATS} (got {})",
            args.repeat
        )));
    }
    let _signal_guard = signals::SignalGuard::install();
    // Validate the configuration (function exists, ramp parameter exists,
    // every parameter's type is one this command knows how to default or
    // ramp) up front, in-process, before spawning any probes — this is
    // just type/spec checking, not invocation, so it carries none of the
    // abort risk documented above, and it means a typo'd --fn or --ramp
    // reports its actual cause instead of the generic "failed at value 1"
    // a swallowed child-process error would otherwise produce.
    let bool_defaults = parse_bool_defaults(&args.bool_defaults)?;
    let (_, env, function, ramp_index) =
        load(&args.contract, &args.function, &args.ramp, args.auth_mode)?;
    validate_bool_defaults(&function, &bool_defaults)?;
    let (plan, ceiling_index) =
        ramp_plan(args.start, args.step, &function.inputs[ramp_index].type_)?;
    let preview = build_args(&env, &function, ramp_index, &bool_defaults, plan.start)?;
    if args.dry_run {
        println!(
            "probe {}={} generated arguments: {preview:?}",
            args.ramp, plan.start
        );
        return Ok(());
    }
    drop(env);

    let self_exe = probe_executable()?;
    // Probes run with a private working directory (see `ProbeScratch`), so
    // the contract path they receive must not depend on this process's cwd.
    let contract = std::fs::canonicalize(&args.contract).map_err(|err| {
        CliError(format!(
            "failed to resolve {}: {err}",
            quote(args.contract.display())
        ))
    })?;
    let scratch = ProbeScratch::create()?;
    let mut failure_kinds: BTreeMap<u32, ProbeExit> = BTreeMap::new();

    // Runs one batch of probes concurrently, then logs them in ramp order.
    // Returns `None` when the run is cancelled before the batch starts.
    // Search indices are converted to ramp values (`plan.value_at`) here, so the
    // bounds logic below works on indices and only the reports see values.
    let mut probe_batch = |indices: &[u32]| -> Result<Option<Vec<bool>>, CliError> {
        if CANCELLED.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let results = probe_concurrently(indices, |index| {
            run_probe_process(
                &self_exe,
                &scratch,
                &contract,
                &args,
                plan.value_at(index),
                Duration::from_secs(args.probe_timeout),
                out.verbosity == super::output::Verbosity::Verbose,
            )
        });
        if CANCELLED.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let mut outcomes = Vec::with_capacity(indices.len());
        for (index, result) in indices.iter().zip(results) {
            let result = result?;
            let value = plan.value_at(*index);
            out.detail(format!(
                "probe {}={value}: {}",
                args.ramp,
                result.outcome.label()
            ));
            if let Some(diagnostic) = &result.diagnostic {
                for line in diagnostic.lines() {
                    out.detail(format!("  child stderr: {line}"));
                }
            }
            let ok = match result.outcome {
                ProbeExit::Success => true,
                ProbeExit::ContractRejected | ProbeExit::HostAborted => {
                    failure_kinds.insert(*index, result.outcome);
                    false
                }
                ProbeExit::TimedOut => {
                    return Err(CliError(format!(
                        "probe {}={value} timed out after {} seconds; inspect the contract or increase --probe-timeout",
                        quote(&args.ramp), args.probe_timeout
                    )));
                }
                ProbeExit::LaunchFailed(reason) => {
                    return Err(CliError(format!(
                        "failed to launch probe {}={value}: {reason}; check the executable and use --verbose",
                        quote(&args.ramp)
                    )));
                }
                ProbeExit::Cancelled => return Ok(None),
            };
            outcomes.push(ok);
        }
        Ok(Some(outcomes))
    };

    // Find a failing upper bound by doubling. A Vec ramp stops at its item cap.
    let (ladder_ok, ladder_failed) =
        match find_ladder_bounds(args.jobs, ceiling_index, &mut probe_batch)? {
            Search::Done(bounds) => bounds,
            Search::Cancelled { last_ok } => {
                return report_interrupted(&args, last_ok.map(|index| plan.value_at(index)))
            }
        };

    if CANCELLED.load(Ordering::Relaxed) {
        return report_interrupted(&args, ladder_ok.map(|index| plan.value_at(index)));
    }

    let Some(last_ok) = ladder_ok else {
        let first = plan.value_at(if ENABLE_ZERO_PROBE { 0 } else { 1 });
        return Err(CliError(format!(
            "{} failed even at the smallest ramp value ({first}) for parameter {}; check that \
             the function succeeds with default arguments (run with --verbose to see each probe), \
             or pass --start with a value it accepts",
            quote(&args.function),
            quote(&args.ramp)
        )));
    };

    // Binary search between the last success and the first failure for a
    // tighter bound, if we found one.
    let mut best = last_ok;
    if let Some(hi_start) = ladder_failed {
        best = match refine_boundary(last_ok, hi_start, args.jobs, &mut probe_batch)? {
            Search::Done(boundary) => boundary,
            Search::Cancelled { last_ok } => {
                return report_interrupted(&args, last_ok.map(|index| plan.value_at(index)))
            }
        };

        // Monotonicity sampling (issue #186) after refinement
        if !CANCELLED.load(Ordering::Relaxed)
            && !sample_monotonicity(best, hi_start, 3, &mut probe_batch)?
        {
            eprintln!(
                "warning: potential non-monotonic behavior detected: {} failed between known-success {} and known-failure {}",
                args.ramp,
                plan.value_at(best),
                plan.value_at(hi_start)
            );
        }
    }

    if CANCELLED.load(Ordering::Relaxed) {
        return report_interrupted(&args, Some(plan.value_at(best)));
    }

    // A cap without an observed failure is not a proven maximum. Failures are
    // keyed by search index; the reports below use ramp values.
    let first_failing_index = ladder_failed.map(|_| best + 1);
    let failure_kind =
        first_failing_index.and_then(|index| failure_kinds.get(&index).map(ProbeExit::label));
    let first_failing = first_failing_index.map(|index| plan.value_at(index));
    let best_value = plan.value_at(best);
    let ceiling = plan.value_at(ceiling_index);

    // Revalidate the boundary (issue #185) before final measurement
    let (contract_id, env, func_spec, ramp_index) =
        load(&args.contract, &args.function, &args.ramp, args.auth_mode)?;
    let func = Symbol::new(&env, &args.function);
    let revalidation_args = build_args(&env, &func_spec, ramp_index, &bool_defaults, best_value)?;
    if !invoke_succeeds(&env, &contract_id, &func, revalidation_args) {
        out.note(format!(
            "warning: boundary revalidation failed for {} = {best_value}; this may indicate \
             nondeterministic contract behavior. consider running limits again.",
            args.ramp
        ));
    }
    drop(env);

    // Measure resources at the best-known-good value, in-process this time
    // (a known-successful call is safe to make directly). Every repeat builds
    // a fresh environment, so the spread shows run-to-run variation.
    let mut cpu_samples = Vec::with_capacity(args.repeat);
    let mut memory_samples = Vec::with_capacity(args.repeat);
    for _ in 0..args.repeat {
        let (instructions, memory_bytes) = measure(&args, best_value, &bool_defaults)?;
        cpu_samples.push(instructions);
        memory_samples.push(memory_bytes);
    }
    let measured = Measured {
        instructions: Spread::of(cpu_samples),
        memory_bytes: Spread::of(memory_samples),
    };
    // For a Vec ramp, the ramp value is the number of items generated.
    let generated_items =
        matches!(function.inputs[ramp_index].type_, ScSpecTypeDef::Vec(_)).then_some(best_value);

    if args.json {
        println!(
            "{}",
            render_json(
                &args,
                best_value,
                &measured,
                first_failing,
                failure_kind,
                ceiling,
                generated_items,
            )
        );
        return Ok(());
    }

    // A Vec ramp's value is an item count, so say what the number counts.
    let unit = if generated_items.is_some() {
        " generated items"
    } else {
        ""
    };
    println!(
        "last successful {} for {:?}: {best_value}{unit}",
        args.ramp, args.function
    );
    println!("  instructions: {}", measured.instructions.describe());
    println!("  memory bytes: {}", measured.memory_bytes.describe());
    match first_failing {
        Some(value) => println!(
            "  first failing {}: {value} ({})",
            args.ramp,
            failure_kind.unwrap_or("unknown")
        ),
        None => println!(
            "  search capped at {ceiling}; no failing probe observed (not a measured maximum)"
        ),
    }
    out.note(
        "  (ledger reads/writes and transaction size are not measured by this command; \
         see --help)",
    );

    Ok(())
}

/// Repeated samples of one resource, summarized. The median of an even count
/// is its lower middle value, so every reported figure was actually observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Spread {
    min: u64,
    median: u64,
    max: u64,
    samples: usize,
}

impl Spread {
    fn of(mut samples: Vec<u64>) -> Self {
        samples.sort_unstable();
        let last = samples.len().saturating_sub(1);
        Self {
            min: samples.first().copied().unwrap_or(0),
            median: samples.get(last / 2).copied().unwrap_or(0),
            max: samples.last().copied().unwrap_or(0),
            samples: samples.len(),
        }
    }

    /// The text report's figure: the value alone for one sample, otherwise the
    /// median with the range it came from.
    fn describe(&self) -> String {
        if self.samples == 1 {
            self.median.to_string()
        } else {
            format!(
                "{} (median of {}; min {}, max {})",
                self.median, self.samples, self.min, self.max
            )
        }
    }
}

/// The measured cost of the final ramp value, for both reported resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Measured {
    instructions: Spread,
    memory_bytes: Spread,
}

/// Renders the result as the `limits --json` document. `instructions` and
/// `memory_bytes` are the medians; `measurements` carries each full spread.
/// `generated_items` is set only for a `Vec` ramp.
fn render_json(
    args: &LimitsArgs,
    best: i64,
    measured: &Measured,
    first_failing: Option<i64>,
    failure_kind: Option<&str>,
    ceiling: i64,
    generated_items: Option<i64>,
) -> String {
    serde_json::json!({
        "schema_version": LIMITS_JSON_SCHEMA_VERSION,
        "contract": args.contract.display().to_string(),
        "function": args.function,
        "ramp": args.ramp,
        "last_successful": best,
        "generated_items": generated_items,
        "instructions": measured.instructions.median,
        "memory_bytes": measured.memory_bytes.median,
        "measurements": {
            "repeats": measured.instructions.samples,
            "instructions": {
                "min": measured.instructions.min,
                "median": measured.instructions.median,
                "max": measured.instructions.max,
            },
            "memory_bytes": {
                "min": measured.memory_bytes.min,
                "median": measured.memory_bytes.median,
                "max": measured.memory_bytes.max,
            },
        },
        "boundary": {
            "kind": boundary_kind(first_failing),
            "search_ceiling": ceiling,
            "first_failing": first_failing,
            "failure_outcome": failure_kind,
        },
    })
    .to_string()
}

/// Locates the executable that probe subprocesses re-invoke.
///
/// `soroban-testkit` is often started through `PATH` or a symlink (for
/// example `~/.cargo/bin` or a package manager's shim directory), so the
/// probe must not assume `argv[0]` is a usable path. The OS-reported
/// executable ([`std::env::current_exe`], which already resolves symlinks
/// on Linux) is preferred; if it is unavailable or no longer exists (the
/// binary was replaced while running), `argv[0]` is resolved instead:
/// relative to the current directory when it contains a path separator,
/// otherwise by searching `PATH`. The result is always absolute, so it
/// stays valid for children started in a different working directory.
fn probe_executable() -> Result<PathBuf, CliError> {
    resolve_probe_executable(
        std::env::current_exe().ok(),
        std::env::args_os().next(),
        std::env::var_os("PATH"),
    )
    .ok_or_else(|| {
        CliError(
            "failed to locate the soroban-testkit executable to start limits probes; \
             run it by its full path"
                .to_string(),
        )
    })
}

/// The pure part of [`probe_executable`], taking its inputs explicitly so
/// every resolution branch is unit-testable.
fn resolve_probe_executable(
    current_exe: Option<PathBuf>,
    argv0: Option<OsString>,
    path_var: Option<OsString>,
) -> Option<PathBuf> {
    if let Some(exe) = current_exe.filter(|exe| exe.is_file()) {
        return Some(std::fs::canonicalize(&exe).unwrap_or(exe));
    }
    let argv0 = PathBuf::from(argv0?);
    if argv0.as_os_str().is_empty() {
        return None;
    }
    if argv0.components().count() > 1 || argv0.is_absolute() {
        // A path (absolute or relative to cwd): canonicalize resolves any
        // symlink and makes it absolute.
        return std::fs::canonicalize(&argv0)
            .ok()
            .filter(|exe| exe.is_file());
    }
    // A bare command name: it was found through PATH.
    std::env::split_paths(&path_var?)
        .filter(|dir| !dir.as_os_str().is_empty())
        .flat_map(|dir| {
            let plain = dir.join(&argv0);
            let with_suffix = (!std::env::consts::EXE_SUFFIX.is_empty()).then(|| {
                dir.join(format!(
                    "{}{}",
                    argv0.display(),
                    std::env::consts::EXE_SUFFIX
                ))
            });
            std::iter::once(plain).chain(with_suffix)
        })
        .find(|candidate| candidate.is_file())
        .and_then(|exe| std::fs::canonicalize(exe).ok())
}

/// A private, per-run working directory for probe subprocesses.
///
/// Every probe child runs with this directory as its current directory and
/// as its `TMPDIR`/`TMP`/`TEMP`, so anything the host or SDK might write
/// relative to the working directory (such as a `test_snapshots/` tree) or
/// to the system temp dir lands here rather than in the user's project.
/// The directory is removed when the guard drops — on success, on error,
/// and on an interrupted search — so a `limits` run leaves no temporary
/// files or snapshot artifacts behind. Probes additionally disable snapshot
/// capture (see [`load`]), so in practice the directory stays empty.
struct ProbeScratch {
    path: PathBuf,
}

impl ProbeScratch {
    fn create() -> Result<Self, CliError> {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let base = std::env::temp_dir();
        let pid = std::process::id();
        // A few attempts covers a stale directory left by a killed run
        // that happened to have the same pid.
        let mut last_err = None;
        for _ in 0..16 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("soroban-testkit-limits-{pid}-{n}"));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) => last_err = Some(err),
            }
        }
        Err(CliError(format!(
            "failed to create a scratch directory for limits probes in {}: {}",
            quote(base.display()),
            last_err.map_or_else(|| "unknown error".to_string(), |err| err.to_string())
        )))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ProbeScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Run one isolated probe. Quiet runs discard diagnostics as before.
/// Verbose runs drain stderr concurrently and retain no more than 8 KiB.
fn run_probe_process(
    self_exe: &Path,
    scratch: &ProbeScratch,
    contract: &Path,
    args: &LimitsArgs,
    value: i64,
    timeout: Duration,
    verbose: bool,
) -> ProbeResult {
    let mut command = Command::new(self_exe);
    command
        .current_dir(scratch.path())
        .env("TMPDIR", scratch.path())
        .env("TMP", scratch.path())
        .env("TEMP", scratch.path())
        .arg("__limits-probe")
        .arg("--contract")
        .arg(contract)
        .arg("--fn")
        .arg(&args.function)
        .arg("--ramp")
        .arg(&args.ramp)
        .arg("--value")
        .arg(value.to_string())
        .arg("--auth-mode")
        .arg(args.auth_mode.as_str());
    for default in &args.bool_defaults {
        command.arg("--bool-default").arg(default);
    }
    command.stdout(Stdio::null()).stderr(if verbose {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ProbeResult {
                outcome: ProbeExit::LaunchFailed(error.to_string()),
                diagnostic: None,
            };
        }
    };
    let reader = child.stderr.take().map(|mut stderr| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut chunk = [0u8; 4096];
            let mut truncated = false;
            loop {
                match stderr.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => {
                        let capacity = MAX_PROBE_STDERR_BYTES.saturating_sub(kept.len());
                        let take = count.min(capacity);
                        kept.extend_from_slice(&chunk[..take]);
                        truncated |= take != count;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let mut message = String::from_utf8_lossy(&kept).into_owned();
            if truncated {
                message.push_str("\n[child stderr truncated at 8192 bytes]");
            }
            message
        })
    });
    let start = Instant::now();
    let outcome = loop {
        if CANCELLED.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            break ProbeExit::Cancelled;
        }
        match child.try_wait() {
            Ok(Some(status)) => break classify_probe_exit(status),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break ProbeExit::TimedOut;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break ProbeExit::LaunchFailed(format!("cannot wait for probe: {error}"));
            }
        }
    };
    let diagnostic = reader
        .and_then(|reader| reader.join().ok())
        .filter(|message| !message.trim().is_empty());
    ProbeResult {
        outcome,
        diagnostic,
    }
}

/// Execute up to eight independent probes, retaining input ordering.
fn probe_concurrently(
    values: &[u32],
    work: impl Fn(u32) -> ProbeResult + Sync,
) -> Vec<Result<ProbeResult, CliError>> {
    std::thread::scope(|scope| {
        let work = &work;
        let workers: Vec<_> = values
            .iter()
            .map(|&value| scope.spawn(move || work(value)))
            .collect();
        workers
            .into_iter()
            .map(|worker| {
                worker.join().map_err(|_| {
                    CliError("an isolated probe worker panicked; re-run with --jobs 1".to_string())
                })
            })
            .collect()
    })
}

/// The doubling ladder value after `value`, or `None` past `ceiling`.
fn ladder_successor(value: u32, ceiling: u32) -> Option<u32> {
    if value == 0 {
        Some(1).filter(|next| *next <= ceiling)
    } else {
        value.checked_mul(2).filter(|next| *next <= ceiling)
    }
}

/// Up to `jobs` consecutive ladder values starting at `start`, never past
/// `ceiling`. A `jobs` of 0 is treated as 1.
fn ladder_batch(start: u32, jobs: usize, ceiling: u32) -> Vec<u32> {
    let mut batch = Vec::new();
    let mut current = Some(start);
    while let Some(value) = current {
        if batch.len() == jobs.max(1) {
            break;
        }
        batch.push(value);
        current = ladder_successor(value, ceiling);
    }
    batch
}

/// The last successful and first failing ladder values, if any.
type LadderBounds = (Option<u32>, Option<u32>);

/// Doubling phase. Probes ladder values in batches of `jobs`, reads each
/// batch in order, and stops at the first failure. Returns the last success
/// and the first failure. Both are `None` when the search reached the ceiling
/// without failing.
fn find_ladder_bounds<P>(
    jobs: usize,
    ceiling: u32,
    mut probe_batch: P,
) -> Result<Search<LadderBounds>, CliError>
where
    P: FnMut(&[u32]) -> Result<Option<Vec<bool>>, CliError>,
{
    let mut last_ok = None;
    let mut next = Some(if ENABLE_ZERO_PROBE { 0u32 } else { 1u32 });
    while let Some(start) = next {
        let batch = ladder_batch(start, jobs, ceiling);
        let Some(results) = probe_batch(&batch)? else {
            return Ok(Search::Cancelled { last_ok });
        };
        for (value, ok) in batch.into_iter().zip(results) {
            if !ok {
                return Ok(Search::Done((last_ok, Some(value))));
            }
            last_ok = Some(value);
            next = ladder_successor(value, ceiling);
        }
    }
    Ok(Search::Done((last_ok, None)))
}

/// Refinement phase. `lo` is a known success and `hi` a known failure.
/// Each round probes up to `jobs` evenly spaced points strictly between
/// them, then keeps the sub-interval that straddles the first failure. With
/// `jobs` = 1 this is the classic midpoint binary search. The search ends
/// when `lo` and `hi` are adjacent, and returns `lo`.
fn refine_boundary<P>(
    mut lo: u32,
    mut hi: u32,
    jobs: usize,
    mut probe_batch: P,
) -> Result<Search<u32>, CliError>
where
    P: FnMut(&[u32]) -> Result<Option<Vec<bool>>, CliError>,
{
    while lo + 1 < hi {
        let gap = hi - lo;
        // At least one point, and never more points than fit strictly inside.
        let count = jobs.max(1).min((gap - 1) as usize);
        let points: Vec<u32> = (1..=count as u32)
            .map(|i| lo + gap * i / (count as u32 + 1))
            .collect();
        let Some(results) = probe_batch(&points)? else {
            return Ok(Search::Cancelled { last_ok: Some(lo) });
        };
        match results.iter().position(|ok| !ok) {
            Some(0) => hi = points[0],
            Some(first_failure) => {
                lo = points[first_failure - 1];
                hi = points[first_failure];
            }
            None => lo = points[count - 1],
        }
    }
    Ok(Search::Done(lo))
}

/// Monotonicity sampling (issue #186): probe a few interior points to detect
/// non-monotonic behavior. Returns true if monotonicity is verified.
fn sample_monotonicity<P>(
    lo: u32,
    hi: u32,
    sample_count: usize,
    mut probe_batch: P,
) -> Result<bool, CliError>
where
    P: FnMut(&[u32]) -> Result<Option<Vec<bool>>, CliError>,
{
    if !ENABLE_MONOTONICITY_CHECK || lo + 1 >= hi {
        return Ok(true);
    }

    let gap = hi - lo;
    let count = sample_count.min((gap - 1) as usize);
    if count == 0 {
        return Ok(true);
    }

    let samples: Vec<u32> = (1..=count as u32)
        .map(|i| lo + gap * i / (count as u32 + 1))
        .collect();

    let Some(results) = probe_batch(&samples)? else {
        return Ok(true); // Treat cancellation as inconclusive
    };

    // Check for monotonicity: all points between lo and hi should succeed
    // since lo is a known success. If any fail, there's non-monotonic behavior.
    // The caller reports it, because it knows the ramp values behind the indices.
    Ok(results.iter().all(|&ok| ok))
}

/// A cancelled run reports its last successful probe without claiming
/// a proven maximum or attempting a fresh WASM invocation.
fn report_interrupted(args: &LimitsArgs, last_ok: Option<i64>) -> Result<(), CliError> {
    match last_ok {
        Some(value) => {
            println!("interrupted; last successful {} for {:?}: {value} (partial result, not a proven maximum)", args.ramp, args.function);
            println!("  resource measurements unavailable after cancellation");
            Ok(())
        }
        None => Err(CliError(format!(
            "limits search interrupted before any successful probe for {:?}",
            args.function
        ))),
    }
}

/// The hidden probe entry point: performs exactly one invocation and
/// returns acceptance separately from setup errors. The CLI assigns a
/// dedicated exit code to contract rejection.
pub fn run_probe(args: ProbeArgs) -> Result<bool, CliError> {
    let _quiet = QuietPanics::install();
    let bool_defaults = parse_bool_defaults(&args.bool_defaults)?;
    let (contract_id, env, function, ramp_index) =
        load(&args.contract, &args.function, &args.ramp, args.auth_mode)?;
    validate_bool_defaults(&function, &bool_defaults)?;
    let args_vec = build_args(&env, &function, ramp_index, &bool_defaults, args.value)?;
    let func = Symbol::new(&env, &args.function);
    let accepted = invoke_succeeds(&env, &contract_id, &func, args_vec);
    if !accepted {
        // The parent captures this only when --verbose is enabled. Normal
        // runs keep the historical quiet behavior.
        eprintln!("contract rejected {}={}", args.ramp, args.value);
    }
    Ok(accepted)
}

fn measure(
    args: &LimitsArgs,
    value: i64,
    bool_defaults: &BTreeMap<String, bool>,
) -> Result<(u64, u64), CliError> {
    let (contract_id, env, function, ramp_index) =
        load(&args.contract, &args.function, &args.ramp, args.auth_mode)?;
    let func = Symbol::new(&env, &args.function);
    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let args_vec = build_args(&env, &function, ramp_index, bool_defaults, value)?;
    if !invoke_succeeds(&env, &contract_id, &func, args_vec) {
        return Err(CliError(
            "internal error: the ramp value chosen as successful failed on re-measurement"
                .to_string(),
        ));
    }
    Ok((budget.cpu_instruction_cost(), budget.memory_bytes_cost()))
}

/// Silences the default panic hook for the duration it's held, restoring
/// the previous hook on drop, so a probe's failure doesn't dump a panic
/// message and the host's diagnostic event log to stderr.
type PanicHook = Box<dyn Fn(&panic::PanicHookInfo<'_>) + Sync + Send>;

struct QuietPanics {
    previous: Option<PanicHook>,
}

impl QuietPanics {
    fn install() -> Self {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        Self {
            previous: Some(previous),
        }
    }
}

impl Drop for QuietPanics {
    fn drop(&mut self) {
        if let Some(hook) = self.previous.take() {
            panic::set_hook(hook);
        }
    }
}

fn load(
    contract: &std::path::Path,
    function: &str,
    ramp: &str,
    auth_mode: AuthMode,
) -> Result<(Address, Env, ScSpecFunctionV0, usize), CliError> {
    let wasm = std::fs::read(contract).map_err(|err| {
        CliError(format!(
            "failed to read {}: {err}; pass the path to a compiled contract .wasm",
            quote(contract.display())
        ))
    })?;

    let entries = soroban_spec::read::from_wasm(&wasm).map_err(|err| spec_error(contract, &err))?;

    let constructor = entries.iter().find_map(|entry| match entry {
        ScSpecEntry::FunctionV0(f) if f.name.to_string() == CONSTRUCTOR_NAME => Some(f.clone()),
        _ => None,
    });
    let func_spec = find_function_spec(entries, contract, function)?;
    let ramp_index = ramp_index_of(&func_spec, function, ramp)?;

    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    // Each probe owns a fresh Env. Apply the selected authorization policy
    // without leaking mocks between probes.
    match auth_mode {
        AuthMode::All => env.mock_all_auths_allowing_non_root_auth(),
        AuthMode::RootOnly => env.mock_all_auths(),
        AuthMode::None => {}
    }
    // A contract with a constructor must be registered with its arguments, or
    // it never initializes. Ramp parameters do not apply to the constructor,
    // so every input receives its normal default.
    let constructor_args = match &constructor {
        Some(ctor) => build_args(&env, ctor, usize::MAX, &BTreeMap::new(), 0)?,
        None => SVec::new(&env),
    };
    let contract_id = env.register(wasm.as_slice(), constructor_args);

    Ok((contract_id, env, func_spec, ramp_index))
}

/// An actionable message for a `.wasm` whose contract spec can't be read.
/// `FromWasmError`'s own `Display` is just "reading wasm" etc., which
/// names neither the file nor the fix.
fn spec_error(contract: &std::path::Path, err: &soroban_spec::read::FromWasmError) -> CliError {
    use soroban_spec::read::FromWasmError;

    let path = quote(contract.display());
    CliError(match err {
        FromWasmError::Read(source) => format!(
            "{path} is not a valid WebAssembly module ({source}); pass a contract built for \
             wasm32v1-none, e.g. target/wasm32v1-none/release/<crate>.wasm"
        ),
        FromWasmError::Parse(source) => format!(
            "{path} has a malformed contract spec ({source}); rebuild it with a current \
             soroban-sdk"
        ),
        FromWasmError::NotFound => format!(
            "{path} has no contract spec (no `contractspecv0` section); is it a Soroban \
             contract built with soroban-sdk?"
        ),
    })
}

/// A Rust-like name for a contract spec type, for error messages, e.g.
/// `Vec<Address>`, `Map<Symbol, u32>` or `Option<BytesN<32>>`, in place
/// of the XDR struct's `Debug` dump.
fn type_name(type_: &ScSpecTypeDef) -> String {
    let simple = match type_ {
        ScSpecTypeDef::Val => "Val",
        ScSpecTypeDef::Bool => "bool",
        ScSpecTypeDef::Void => "()",
        ScSpecTypeDef::Error => "Error",
        ScSpecTypeDef::U32 => "u32",
        ScSpecTypeDef::I32 => "i32",
        ScSpecTypeDef::U64 => "u64",
        ScSpecTypeDef::I64 => "i64",
        ScSpecTypeDef::Timepoint => "Timepoint",
        ScSpecTypeDef::Duration => "Duration",
        ScSpecTypeDef::U128 => "u128",
        ScSpecTypeDef::I128 => "i128",
        ScSpecTypeDef::U256 => "U256",
        ScSpecTypeDef::I256 => "I256",
        ScSpecTypeDef::Bytes => "Bytes",
        ScSpecTypeDef::String => "String",
        ScSpecTypeDef::Symbol => "Symbol",
        ScSpecTypeDef::Address => "Address",
        ScSpecTypeDef::MuxedAddress => "MuxedAddress",
        ScSpecTypeDef::Option(option) => {
            return format!("Option<{}>", type_name(&option.value_type))
        }
        ScSpecTypeDef::Result(result) => {
            return format!(
                "Result<{}, {}>",
                type_name(&result.ok_type),
                type_name(&result.error_type)
            )
        }
        ScSpecTypeDef::Vec(vec) => return format!("Vec<{}>", type_name(&vec.element_type)),
        ScSpecTypeDef::Map(map) => {
            return format!(
                "Map<{}, {}>",
                type_name(&map.key_type),
                type_name(&map.value_type)
            )
        }
        ScSpecTypeDef::Tuple(tuple) => {
            let items: Vec<String> = tuple.value_types.iter().map(type_name).collect();
            return format!("({})", items.join(", "));
        }
        ScSpecTypeDef::BytesN(bytes) => return format!("BytesN<{}>", bytes.n),
        ScSpecTypeDef::Udt(udt) => return udt.name.to_utf8_string_lossy(),
    };
    simple.to_string()
}

/// Picks `function` out of a contract's spec entries. Split out of [`load`]
/// so the lookup can be tested against hand-built spec fixtures, without a
/// compiled `.wasm`.
fn find_function_spec(
    entries: Vec<ScSpecEntry>,
    contract: &std::path::Path,
    function: &str,
) -> Result<ScSpecFunctionV0, CliError> {
    if function.starts_with("__") {
        return Err(CliError(format!(
            "{} is a reserved contract name, not a function that can be ramped; \
             the constructor runs at deployment and is handled automatically",
            quote(function)
        )));
    }
    entries
        .into_iter()
        .find_map(|entry| match entry {
            ScSpecEntry::FunctionV0(f) if f.name.to_string() == function => Some(f),
            _ => None,
        })
        .ok_or_else(|| {
            CliError(format!(
                "no function named {} in {}'s spec; check the --fn name",
                quote(function),
                quote(contract.display())
            ))
        })
}

/// Returns the position of the `--ramp` parameter in `func_spec`'s inputs.
fn ramp_index_of(
    func_spec: &ScSpecFunctionV0,
    function: &str,
    ramp: &str,
) -> Result<usize, CliError> {
    func_spec
        .inputs
        .iter()
        .position(|input| input.name.to_utf8_string_lossy() == ramp)
        .ok_or_else(|| {
            let params: Vec<String> = func_spec
                .inputs
                .iter()
                .map(|input| quote(input.name.to_utf8_string_lossy()))
                .collect();
            let params = if params.is_empty() {
                "it takes no parameters".to_string()
            } else {
                format!("its parameters are {}", params.join(", "))
            };
            CliError(format!(
                "{} has no parameter named {}; {params}",
                quote(function),
                quote(ramp)
            ))
        })
}

/// Parses repeatable `--bool-default PARAM=BOOL` values.
fn parse_bool_defaults(values: &[String]) -> Result<BTreeMap<String, bool>, CliError> {
    let mut defaults = BTreeMap::new();
    for value in values {
        let (name, raw) = value.split_once('=').ok_or_else(|| {
            CliError(format!(
                "invalid bool default {}; expected PARAM=true or PARAM=false",
                quote(value)
            ))
        })?;
        if name.is_empty() {
            return Err(CliError(format!(
                "invalid bool default {}; parameter name cannot be empty",
                quote(value)
            )));
        }
        let parsed = match raw {
            "true" => true,
            "false" => false,
            _ => {
                return Err(CliError(format!(
                    "invalid bool default {}; value must be true or false",
                    quote(raw)
                )))
            }
        };
        if defaults.insert(name.to_string(), parsed).is_some() {
            return Err(CliError(format!(
                "bool default for {} was provided more than once",
                quote(name)
            )));
        }
    }
    Ok(defaults)
}

/// Reject overrides that do not refer to bool inputs in the selected function.
fn validate_bool_defaults(
    function: &ScSpecFunctionV0,
    defaults: &BTreeMap<String, bool>,
) -> Result<(), CliError> {
    for name in defaults.keys() {
        let Some(input) = function
            .inputs
            .iter()
            .find(|input| input.name.to_utf8_string_lossy().as_str() == name.as_str())
        else {
            return Err(CliError(format!(
                "bool default refers to unknown parameter {}",
                quote(name)
            )));
        };
        if !matches!(input.type_, ScSpecTypeDef::Bool) {
            return Err(CliError(format!(
                "bool default for {} cannot be applied to parameter type {}",
                quote(name),
                quote(type_name(&input.type_))
            )));
        }
    }
    Ok(())
}

fn build_args(
    env: &Env,
    function: &ScSpecFunctionV0,
    ramp_index: usize,
    bool_defaults: &BTreeMap<String, bool>,
    ramp_value: i64,
) -> Result<SVec<Val>, CliError> {
    let admin = Address::generate(env);
    let mut vals = SVec::new(env);
    for (i, input) in function.inputs.iter().enumerate() {
        let val = if i == ramp_index {
            ramp_val(env, &input.type_, ramp_value)?
        } else {
            default_val(
                env,
                &admin,
                &input.type_,
                input,
                bool_defaults
                    .get(&input.name.to_utf8_string_lossy())
                    .copied(),
            )?
        };
        vals.push_back(val);
    }
    Ok(vals)
}

fn invoke_succeeds(env: &Env, contract_id: &Address, func: &Symbol, args: SVec<Val>) -> bool {
    // try_invoke_contract is the SDK's own no-panic call path, used here
    // so a probe that succeeds doesn't need catch_unwind at all — only a
    // *failing* real-WASM call risks the process abort documented above,
    // and that only ever happens in the isolated child process.
    matches!(
        env.try_invoke_contract::<Val, soroban_sdk::Error>(contract_id, func, args),
        Ok(Ok(_))
    )
}

fn ramp_val(env: &Env, type_: &ScSpecTypeDef, ramp_value: i64) -> Result<Val, CliError> {
    match type_ {
        ScSpecTypeDef::U32 => Ok(ramp_int::<u32>(ramp_value, type_)?.into_val(env)),
        ScSpecTypeDef::I32 => Ok(ramp_int::<i32>(ramp_value, type_)?.into_val(env)),
        ScSpecTypeDef::U64 => Ok(ramp_int::<u64>(ramp_value, type_)?.into_val(env)),
        ScSpecTypeDef::I64 => Ok(ramp_int::<i64>(ramp_value, type_)?.into_val(env)),
        ScSpecTypeDef::U128 => Ok(ramp_int::<u128>(ramp_value, type_)?.into_val(env)),
        ScSpecTypeDef::I128 => Ok(ramp_int::<i128>(ramp_value, type_)?.into_val(env)),
        ScSpecTypeDef::Vec(inner) => {
            let element = &inner.element_type;
            // Checked before the loop, so an unsupported element type is
            // rejected even when the ramp value is 0.
            ramp_item(env, element)?;
            if ramp_value < 0 {
                return Err(CliError(format!(
                    "a Vec ramp cannot generate {ramp_value} items; use a --start of 0 or more"
                )));
            }
            if ramp_value > i64::from(MAX_VEC_RAMP_ITEMS) {
                return Err(CliError(format!(
                    "a Vec ramp generates at most {MAX_VEC_RAMP_ITEMS} items; refusing {ramp_value}"
                )));
            }
            let mut items = SVec::<Val>::new(env);
            for _ in 0..ramp_value {
                items.push_back(ramp_item(env, element)?);
            }
            Ok(items.into_val(env))
        }
        other => Err(unsupported_ramp_type(other)),
    }
}

/// Where a ramp search starts and how far apart its values are. Search index
/// `k` probes the ramp value `start + k * step`. The search doubles `k` (0, 1,
/// 2, 4, ...), so the probes are start, start + step, start + 2 * step,
/// start + 4 * step, and so on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RampPlan {
    start: i64,
    step: i64,
}

impl RampPlan {
    fn value_at(self, index: u32) -> i64 {
        self.start + i64::from(index) * self.step
    }

    /// The largest index whose value stays within `lo..=hi`. `start` must
    /// already lie in that range, and `step` must not be 0.
    fn max_index(self, lo: i64, hi: i64) -> u32 {
        let steps = if self.step > 0 {
            (hi - self.start) / self.step
        } else {
            (self.start - lo) / -self.step
        };
        u32::try_from(steps).unwrap_or(u32::MAX)
    }
}

/// The inclusive range of ramp values a search may probe for `type_`: the
/// type's own range, limited to [`SEARCH_CEILING`] in magnitude, or
/// `0..=MAX_VEC_RAMP_ITEMS` for a `Vec`.
fn ramp_limits(type_: &ScSpecTypeDef) -> Result<(i64, i64), CliError> {
    let cap = i64::from(SEARCH_CEILING);
    let (lo, hi) = match type_ {
        ScSpecTypeDef::Vec(_) => return Ok((0, i64::from(MAX_VEC_RAMP_ITEMS))),
        ScSpecTypeDef::U32 => (0, i64::from(u32::MAX)),
        ScSpecTypeDef::I32 => (i64::from(i32::MIN), i64::from(i32::MAX)),
        // 64-bit and 128-bit ramps are limited to i64 here, which the search cap
        // is well inside.
        ScSpecTypeDef::U64 | ScSpecTypeDef::U128 => (0, i64::MAX),
        ScSpecTypeDef::I64 | ScSpecTypeDef::I128 => (i64::MIN, i64::MAX),
        other => return Err(unsupported_ramp_type(other)),
    };
    Ok((lo.max(-cap), hi.min(cap)))
}

/// Checks `--start` and `--step` against the ramp parameter's type. Returns
/// the search plan and the largest search index it may use.
fn ramp_plan(start: i64, step: i64, type_: &ScSpecTypeDef) -> Result<(RampPlan, u32), CliError> {
    let (lo, hi) = ramp_limits(type_)?;
    let ty = quote(type_name(type_));
    if !(lo..=hi).contains(&start) {
        return Err(CliError(format!(
            "--start {start} is outside the values a {ty} ramp can take ({lo} to {hi})"
        )));
    }
    if step == 0 {
        return Err(CliError(
            "--step must not be 0; use a negative value to probe downwards".to_string(),
        ));
    }
    if step.unsigned_abs() > (hi - lo).unsigned_abs() {
        return Err(CliError(format!(
            "--step {step} is larger than the range of a {ty} ramp ({lo} to {hi})"
        )));
    }
    let plan = RampPlan { start, step };
    Ok((plan, plan.max_index(lo, hi)))
}

/// Converts a ramp value to the integer type `type_` names, refusing a value
/// that type cannot hold (for example a negative value for `u32`).
fn ramp_int<T: TryFrom<i64>>(value: i64, type_: &ScSpecTypeDef) -> Result<T, CliError> {
    T::try_from(value).map_err(|_| {
        CliError(format!(
            "ramp value {value} is outside the range of {}; choose a --start and --step \
             that stay within it",
            quote(type_name(type_))
        ))
    })
}

/// One item of a ramped `Vec`. Addresses are distinct; every other element
/// gets the value [`default_val`] would give that type.
fn ramp_item(env: &Env, element: &ScSpecTypeDef) -> Result<Val, CliError> {
    Ok(match element {
        ScSpecTypeDef::Address => Address::generate(env).into_val(env),
        ScSpecTypeDef::Bool => false.into_val(env),
        ScSpecTypeDef::U32 => 1u32.into_val(env),
        ScSpecTypeDef::I32 => 1i32.into_val(env),
        ScSpecTypeDef::U64 => 1u64.into_val(env),
        ScSpecTypeDef::I64 => 1i64.into_val(env),
        ScSpecTypeDef::U128 => 1u128.into_val(env),
        ScSpecTypeDef::I128 => 1i128.into_val(env),
        ScSpecTypeDef::Symbol => Symbol::new(env, "x").into_val(env),
        ScSpecTypeDef::String => soroban_sdk::String::from_str(env, "").into_val(env),
        ScSpecTypeDef::Bytes => soroban_sdk::Bytes::new(env).into_val(env),
        other => return Err(unsupported_ramp_type(other)),
    })
}

fn unsupported_ramp_type(type_: &ScSpecTypeDef) -> CliError {
    CliError(format!(
        "the ramp parameter's type ({}) isn't supported yet; supported ramp types \
         are u32/i32/u64/i64/u128/i128 and Vec<T> where T is Address, bool, an \
         integer, Symbol, String or Bytes",
        quote(type_name(type_))
    ))
}

fn default_val(
    env: &Env,
    admin: &Address,
    type_: &ScSpecTypeDef,
    input: &ScSpecFunctionInputV0,
    bool_default: Option<bool>,
) -> Result<Val, CliError> {
    match type_ {
        // A parameter literally named `token` is, by overwhelming Soroban
        // convention, a token contract address — and a batch/payout-style
        // function will call transfer() on it and needs `admin` to hold a
        // real balance, not just a syntactically valid address. Deploying
        // a funded Stellar Asset Contract for this one case is a
        // name-based heuristic, not a semantic guarantee, but it's what
        // makes `limits` usable against a real payout contract at all
        // (verified against sororail-contracts' batch_payout, whose
        // execute_equal(funder, token, recipients, amount_each) is
        // exactly this shape).
        ScSpecTypeDef::Address if input.name.to_utf8_string_lossy() == "token" => {
            let issuer = Address::generate(env);
            let sac = env.register_stellar_asset_contract_v2(issuer.clone());
            let token_address = sac.address();
            let amount = i128::MAX / 2;
            StellarAssetClient::new(env, &token_address)
                .mock_auths(&[MockAuth {
                    address: &issuer,
                    invoke: &MockAuthInvoke {
                        contract: &token_address,
                        fn_name: "mint",
                        args: (admin.clone(), amount).into_val(env),
                        sub_invokes: &[],
                    },
                }])
                .mint(admin, &amount);
            Ok(token_address.into_val(env))
        }
        ScSpecTypeDef::Address => Ok(admin.into_val(env)),
        ScSpecTypeDef::Bool => Ok(bool_default.unwrap_or(false).into_val(env)),
        // 1, not 0: verified against sororail-contracts' batch_payout,
        // whose execute_equal(..., amount_each: i128) requires a positive
        // amount and rejects 0 with its own InvalidAmount error before
        // any resource-limit-relevant work happens. There's no default
        // that's safe for every contract's validation rules, but 1 is
        // the smaller mistake: far more contracts reject a non-positive
        // amount than reject exactly 1.
        ScSpecTypeDef::U32 => Ok(1u32.into_val(env)),
        ScSpecTypeDef::I32 => Ok(1i32.into_val(env)),
        ScSpecTypeDef::U64 => Ok(1u64.into_val(env)),
        ScSpecTypeDef::I64 => Ok(1i64.into_val(env)),
        ScSpecTypeDef::U128 => Ok(1u128.into_val(env)),
        ScSpecTypeDef::I128 => Ok(1i128.into_val(env)),
        ScSpecTypeDef::Symbol => Ok(Symbol::new(env, "x").into_val(env)),
        ScSpecTypeDef::String => Ok(soroban_sdk::String::from_str(env, "").into_val(env)),
        ScSpecTypeDef::Bytes => Ok(soroban_sdk::Bytes::new(env).into_val(env)),
        ScSpecTypeDef::Vec(_) => Ok(SVec::<Val>::new(env).into_val(env)),
        // None: an omitted optional argument is the default a caller would send.
        ScSpecTypeDef::Option(_) => Ok(Option::<u32>::None.into_val(env)),
        other => Err(CliError(format!(
            "parameter {} has type {}, which this command doesn't know how to \
             default yet; every parameter other than --ramp needs one of Address, bool, \
             u32/i32/u64/i64/u128/i128, Symbol, String, Bytes, Vec or Option",
            quote(input.name.to_utf8_string_lossy()),
            quote(type_name(other))
        ))),
    }
}

#[cfg(test)]
#[path = "limits/probe_tests.rs"]
mod probe_tests;

/// Spec fixtures built by hand from the XDR types, so the parsing and
/// ramp/default logic is tested for every supported `ScSpecTypeDef` without
/// building a `.wasm` first.
#[cfg(test)]
mod tests {
    use soroban_sdk::xdr::{
        ScSpecTypeBytesN, ScSpecTypeMap, ScSpecTypeOption, ScSpecTypeResult, ScSpecTypeTuple,
        ScSpecTypeUdt, ScSpecTypeVec, ScSymbol,
    };

    use super::*;

    /// A uniquely named, self-removing temp dir for one unit test.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "soroban-testkit-limits-unit-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fake_exe(dir: &Path, name: &str) -> PathBuf {
        let exe = dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"").unwrap();
        exe
    }

    #[test]
    fn probe_executable_prefers_the_os_reported_executable() {
        let dir = TestDir::new("prefers-current-exe");
        let exe = fake_exe(&dir.0, "soroban-testkit");
        let resolved =
            resolve_probe_executable(Some(exe.clone()), Some("something-else".into()), None);
        assert_eq!(resolved, Some(std::fs::canonicalize(exe).unwrap()));
    }

    #[test]
    fn probe_executable_falls_back_to_a_path_search_for_a_bare_argv0() {
        let dir = TestDir::new("path-search");
        let bin = dir.0.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = fake_exe(&bin, "soroban-testkit");
        let path_var =
            std::env::join_paths([dir.0.join("missing"), PathBuf::new(), bin.clone()]).unwrap();
        let resolved = resolve_probe_executable(
            Some(dir.0.join("deleted-binary")),
            Some("soroban-testkit".into()),
            Some(path_var),
        );
        assert_eq!(resolved, Some(std::fs::canonicalize(exe).unwrap()));
    }

    #[test]
    fn probe_executable_resolves_an_argv0_path_to_an_absolute_path() {
        let dir = TestDir::new("argv0-path");
        let exe = fake_exe(&dir.0, "soroban-testkit");
        let resolved = resolve_probe_executable(None, Some(exe.clone().into()), None).unwrap();
        assert!(resolved.is_absolute(), "{resolved:?}");
        assert_eq!(resolved, std::fs::canonicalize(exe).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn probe_executable_resolves_a_symlinked_argv0_to_its_target() {
        let dir = TestDir::new("argv0-symlink");
        let exe = fake_exe(&dir.0, "real-soroban-testkit");
        let link = dir.0.join("soroban-testkit");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let resolved = resolve_probe_executable(None, Some(link.into()), None);
        assert_eq!(resolved, Some(std::fs::canonicalize(exe).unwrap()));
    }

    #[test]
    fn probe_executable_is_none_when_nothing_resolves() {
        let dir = TestDir::new("unresolvable");
        assert_eq!(resolve_probe_executable(None, None, None), None);
        assert_eq!(resolve_probe_executable(None, Some("".into()), None), None);
        assert_eq!(
            resolve_probe_executable(
                Some(dir.0.join("gone")),
                Some("soroban-testkit-not-on-path".into()),
                Some(std::env::join_paths([dir.0.clone()]).unwrap()),
            ),
            None
        );
    }

    #[test]
    fn probe_scratch_dirs_are_unique_and_removed_on_drop() {
        let first = ProbeScratch::create().unwrap();
        let second = ProbeScratch::create().unwrap();
        assert_ne!(first.path(), second.path());
        let path = first.path().to_path_buf();
        assert!(path.is_dir());
        std::fs::create_dir_all(path.join("test_snapshots")).unwrap();
        std::fs::write(path.join("test_snapshots").join("probe.json"), b"{}").unwrap();
        drop(first);
        assert!(!path.exists(), "scratch dir must be removed: {path:?}");
    }

    /// A probe where a value succeeds exactly when it is at most `threshold`.
    fn threshold_probe(
        threshold: u32,
    ) -> impl FnMut(&[u32]) -> Result<Option<Vec<bool>>, CliError> {
        move |values: &[u32]| -> Result<Option<Vec<bool>>, CliError> {
            Ok(Some(values.iter().map(|v| *v <= threshold).collect()))
        }
    }

    /// The boundary `run` reports for `threshold`: doubling, then refinement.
    fn boundary_for(threshold: u32, jobs: usize) -> Option<u32> {
        let bounds =
            match find_ladder_bounds(jobs, SEARCH_CEILING, threshold_probe(threshold)).unwrap() {
                Search::Done(bounds) => bounds,
                Search::Cancelled { .. } => unreachable!("no cancellation in this test"),
            };
        let (last_ok, first_failed) = bounds;
        let last_ok = last_ok?;
        let Some(hi) = first_failed else {
            return Some(last_ok);
        };
        match refine_boundary(last_ok, hi, jobs, threshold_probe(threshold)).unwrap() {
            Search::Done(boundary) => Some(boundary),
            Search::Cancelled { .. } => unreachable!("no cancellation in this test"),
        }
    }

    #[test]
    fn boundary_is_the_same_for_every_jobs_value() {
        let thresholds = [
            0, // Test zero threshold (issue #187)
            1,
            2,
            3,
            5,
            7,
            8,
            100,
            1000,
            SEARCH_CEILING - 1,
            SEARCH_CEILING,
            u32::MAX,
        ];
        for threshold in thresholds {
            let expected = threshold.min(SEARCH_CEILING);
            for jobs in 1..=MAX_JOBS {
                assert_eq!(
                    boundary_for(threshold, jobs),
                    Some(expected),
                    "threshold {threshold}, jobs {jobs}"
                );
            }
        }
    }

    #[test]
    fn capped_search_is_not_a_measured_failure() {
        let result = find_ladder_bounds(4, SEARCH_CEILING, threshold_probe(u32::MAX)).unwrap();
        assert_eq!(result, Search::Done((Some(SEARCH_CEILING), None)));
        assert_eq!(boundary_kind(None), "search_cap_reached");
        assert_eq!(
            boundary_kind(Some(i64::from(SEARCH_CEILING))),
            "measured_failure"
        );
    }

    #[test]
    fn a_failing_first_value_leaves_no_success() {
        assert_eq!(
            find_ladder_bounds(4, SEARCH_CEILING, |values: &[u32]| {
                Ok(Some(vec![false; values.len()]))
            })
            .unwrap(),
            Search::Done((None, Some(0)))
        );
    }

    #[test]
    fn zero_probe_starts_at_zero_when_enabled() {
        // When ENABLE_ZERO_PROBE is true, the first probe should be at 0
        assert_eq!(
            ladder_batch(if ENABLE_ZERO_PROBE { 0 } else { 1 }, 1, SEARCH_CEILING),
            vec![if ENABLE_ZERO_PROBE { 0 } else { 1 }]
        );
    }

    #[test]
    fn ladder_successor_handles_zero() {
        assert_eq!(ladder_successor(0, SEARCH_CEILING), Some(1));
        assert_eq!(ladder_successor(1, SEARCH_CEILING), Some(2));
        assert_eq!(ladder_successor(2, SEARCH_CEILING), Some(4));
        assert_eq!(ladder_successor(0, 0), None);
    }

    #[test]
    fn each_batch_uses_exactly_the_requested_concurrency() {
        for jobs in 1..=MAX_JOBS {
            let mut inner = threshold_probe(1000);
            let mut largest_batch = 0;
            let mut probe = |values: &[u32]| {
                largest_batch = largest_batch.max(values.len());
                inner(values)
            };
            let Search::Done((Some(lo), Some(hi))) =
                find_ladder_bounds(jobs, SEARCH_CEILING, &mut probe).unwrap()
            else {
                panic!("expected a bracket around 1000 for jobs {jobs}");
            };
            refine_boundary(lo, hi, jobs, &mut probe).unwrap();
            assert_eq!(largest_batch, jobs, "jobs {jobs}");
        }
    }

    #[test]
    fn cancellation_mid_search_keeps_the_last_success() {
        let mut calls = 0;
        let mut probe = |values: &[u32]| -> Result<Option<Vec<bool>>, CliError> {
            calls += 1;
            if calls == 1 {
                Ok(Some(values.iter().map(|_| true).collect()))
            } else {
                Ok(None)
            }
        };
        assert_eq!(
            find_ladder_bounds(2, SEARCH_CEILING, &mut probe).unwrap(),
            Search::Cancelled { last_ok: Some(1) }
        );
    }

    #[test]
    fn ladder_batches_double_and_stop_at_the_ceiling() {
        assert_eq!(ladder_batch(1, 1, SEARCH_CEILING), vec![1]);
        assert_eq!(ladder_batch(1, 3, SEARCH_CEILING), vec![1, 2, 4]);
        assert_eq!(
            ladder_batch(1 << 23, 4, SEARCH_CEILING),
            vec![1 << 23, 1 << 24]
        );
        assert_eq!(ladder_batch(1 << 24, 4, SEARCH_CEILING), vec![1 << 24]);
        assert_eq!(ladder_batch(2, 0, SEARCH_CEILING), vec![2]);
        // A Vec ramp stops at its own, much smaller, item cap.
        assert_eq!(ladder_batch(512, 4, MAX_VEC_RAMP_ITEMS), vec![512, 1024]);
    }

    #[test]
    fn concurrent_probes_return_results_in_input_order() {
        let values = [4, 1, 6, 3];
        let results = probe_concurrently(&values, |value| {
            // Later values finish first, so completion order differs from input order.
            std::thread::sleep(std::time::Duration::from_millis(u64::from(10 - value)));
            ProbeResult {
                outcome: if value % 2 == 1 {
                    ProbeExit::Success
                } else {
                    ProbeExit::ContractRejected
                },
                diagnostic: None,
            }
        });
        let outcomes: Vec<bool> = results
            .into_iter()
            .map(|r| r.unwrap().outcome == ProbeExit::Success)
            .collect();
        assert_eq!(outcomes, vec![false, true, false, true]);
    }

    #[test]
    fn jobs_outside_one_to_eight_is_rejected_before_loading_the_contract() {
        for jobs in [0, MAX_JOBS + 1] {
            let args = LimitsArgs {
                contract: "missing.wasm".into(),
                function: "run".into(),
                ramp: "amount".into(),
                start: 0,
                step: 1,
                jobs,
                probe_timeout: 120,
                repeat: 1,
                dry_run: false,
                bool_defaults: Vec::new(),
                auth_mode: AuthMode::All,
                json: false,
            };
            let out = crate::commands::output::Output {
                verbosity: crate::commands::output::Verbosity::Quiet,
                color: false,
            };
            let err = run(args, out).unwrap_err();
            assert_eq!(
                err.0,
                format!("--jobs must be between 1 and 8 (got {jobs})")
            );
        }
    }

    #[test]
    fn cancellation_without_success_is_an_error() {
        let args = LimitsArgs {
            contract: "test.wasm".into(),
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
        };
        let err = report_interrupted(&args, None).expect_err("no successful result");
        assert!(err.0.contains("before any successful probe"));
        assert!(report_interrupted(&args, Some(7)).is_ok());
    }

    fn vec_of(element: ScSpecTypeDef) -> ScSpecTypeDef {
        ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(element),
        }))
    }

    fn input(name: &str, type_: ScSpecTypeDef) -> ScSpecFunctionInputV0 {
        ScSpecFunctionInputV0 {
            doc: "".try_into().expect("empty doc fits"),
            name: name.try_into().expect("fixture name fits in 30 bytes"),
            type_,
        }
    }

    fn function(name: &str, inputs: Vec<ScSpecFunctionInputV0>) -> ScSpecFunctionV0 {
        ScSpecFunctionV0 {
            doc: "".try_into().expect("empty doc fits"),
            name: ScSymbol(name.try_into().expect("fixture name fits in 32 bytes")),
            inputs: inputs.try_into().expect("fixture has at most 10 inputs"),
            outputs: Vec::<ScSpecTypeDef>::new().try_into().expect("no outputs"),
        }
    }

    /// Every type `--ramp` accepts. Keep in sync with [`ramp_val`].
    fn ramp_types() -> Vec<ScSpecTypeDef> {
        vec![
            ScSpecTypeDef::U32,
            ScSpecTypeDef::I32,
            ScSpecTypeDef::U64,
            ScSpecTypeDef::I64,
            ScSpecTypeDef::U128,
            ScSpecTypeDef::I128,
            vec_of(ScSpecTypeDef::Address),
        ]
    }

    /// Every type a non-ramp parameter can default to. Keep in sync with
    /// [`default_val`].
    fn default_types() -> Vec<ScSpecTypeDef> {
        vec![
            ScSpecTypeDef::Address,
            ScSpecTypeDef::Bool,
            ScSpecTypeDef::U32,
            ScSpecTypeDef::I32,
            ScSpecTypeDef::U64,
            ScSpecTypeDef::I64,
            ScSpecTypeDef::U128,
            ScSpecTypeDef::I128,
            ScSpecTypeDef::Symbol,
            ScSpecTypeDef::String,
            ScSpecTypeDef::Bytes,
            vec_of(ScSpecTypeDef::U32),
            ScSpecTypeDef::Option(Box::new(soroban_sdk::xdr::ScSpecTypeOption {
                value_type: Box::new(ScSpecTypeDef::U32),
            })),
        ]
    }

    #[test]
    fn finds_the_named_function_among_other_entries() {
        let entries = vec![
            ScSpecEntry::FunctionV0(function("deposit", vec![])),
            ScSpecEntry::FunctionV0(function("batch_payout", vec![])),
        ];
        let found = find_function_spec(entries, std::path::Path::new("vault.wasm"), "batch_payout")
            .expect("batch_payout is in the spec");
        assert_eq!(found.name.to_string(), "batch_payout");
    }

    #[test]
    fn reports_a_missing_function_with_the_contract_path() {
        let err = find_function_spec(
            vec![ScSpecEntry::FunctionV0(function("deposit", vec![]))],
            std::path::Path::new("vault.wasm"),
            "withdraw",
        )
        .expect_err("withdraw is not in the spec");
        assert!(err.0.contains("no function named `withdraw`"), "{err}");
        assert!(err.0.contains("`vault.wasm`"), "{err}");
    }

    #[test]
    fn finds_the_ramp_parameter_position() {
        let func = function(
            "batch_payout",
            vec![
                input("funder", ScSpecTypeDef::Address),
                input("recipients", vec_of(ScSpecTypeDef::Address)),
            ],
        );
        assert_eq!(
            ramp_index_of(&func, "batch_payout", "recipients").expect("recipients is an input"),
            1
        );
    }

    #[test]
    fn reports_a_missing_ramp_parameter() {
        let func = function(
            "batch_payout",
            vec![input("funder", ScSpecTypeDef::Address)],
        );
        let err = ramp_index_of(&func, "batch_payout", "recipients").expect_err("no such input");
        assert!(
            err.0
                .contains("`batch_payout` has no parameter named `recipients`"),
            "{err}"
        );
        assert!(err.0.contains("its parameters are `funder`"), "{err}");
    }

    #[test]
    fn every_supported_ramp_type_builds_a_value() {
        let env = Env::default();
        for ty in ramp_types() {
            assert!(
                ramp_val(&env, &ty, 3).is_ok(),
                "ramp type {ty:?} should be supported"
            );
        }
    }

    #[test]
    fn unsupported_ramp_types_are_rejected_with_an_actionable_message() {
        let env = Env::default();
        for ty in [
            ScSpecTypeDef::Bool,
            ScSpecTypeDef::Symbol,
            ScSpecTypeDef::String,
        ] {
            let err = ramp_val(&env, &ty, 3).expect_err("not a ramp type");
            assert!(err.0.contains("isn't supported yet"), "{err}");
            assert!(err.0.contains("u32/i32/u64/i64/u128/i128"), "{err}");
        }
    }

    #[test]
    fn bool_defaults_parse_true_and_false_and_reject_invalid_values() {
        let parsed =
            parse_bool_defaults(&["enabled=true".to_string(), "paused=false".to_string()]).unwrap();
        assert_eq!(parsed.get("enabled"), Some(&true));
        assert_eq!(parsed.get("paused"), Some(&false));

        for invalid in [
            vec!["enabled".to_string()],
            vec!["=true".to_string()],
            vec!["enabled=yes".to_string()],
            vec!["enabled=true".to_string(), "enabled=false".to_string()],
        ] {
            assert!(parse_bool_defaults(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn bool_default_overrides_are_converted_to_soroban_values() {
        use soroban_sdk::TryFromVal;

        let env = Env::default();
        let admin = Address::generate(&env);
        let fixture = input("enabled", ScSpecTypeDef::Bool);
        let enabled = default_val(&env, &admin, &fixture.type_, &fixture, Some(true)).unwrap();
        let disabled = default_val(&env, &admin, &fixture.type_, &fixture, Some(false)).unwrap();
        assert!(bool::try_from_val(&env, &enabled).unwrap());
        assert!(!bool::try_from_val(&env, &disabled).unwrap());
    }

    #[test]
    fn bool_defaults_must_match_a_bool_parameter() {
        let func = function(
            "run",
            vec![
                input("enabled", ScSpecTypeDef::Bool),
                input("amount", ScSpecTypeDef::U32),
            ],
        );
        assert!(
            validate_bool_defaults(&func, &BTreeMap::from([("enabled".to_string(), true)])).is_ok()
        );
        assert!(
            validate_bool_defaults(&func, &BTreeMap::from([("missing".to_string(), true)]))
                .unwrap_err()
                .0
                .contains("unknown parameter")
        );
        assert!(
            validate_bool_defaults(&func, &BTreeMap::from([("amount".to_string(), true)]))
                .unwrap_err()
                .0
                .contains("cannot be applied")
        );
    }

    #[test]
    fn every_supported_default_type_builds_a_value() {
        let env = Env::default();
        let admin = soroban_sdk::Address::generate(&env);
        for ty in default_types() {
            let fixture = input("param", ty.clone());
            assert!(
                default_val(&env, &admin, &ty, &fixture, None).is_ok(),
                "default type {ty:?} should be supported"
            );
        }
    }

    #[test]
    fn a_parameter_named_token_gets_a_funded_token_contract() {
        let env = Env::default();
        let admin = soroban_sdk::Address::generate(&env);
        let fixture = input("token", ScSpecTypeDef::Address);
        assert!(default_val(&env, &admin, &ScSpecTypeDef::Address, &fixture, None).is_ok());
    }

    #[test]
    fn unknown_default_types_are_rejected_with_an_actionable_message() {
        let env = Env::default();
        let admin = soroban_sdk::Address::generate(&env);
        let ty = ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::Symbol),
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        let fixture = input("balances", ty.clone());
        let err = default_val(&env, &admin, &ty, &fixture, None).expect_err("Map has no default");
        assert!(err.0.contains("doesn't know how to default"), "{err}");
        assert!(
            err.0
                .contains("parameter `balances` has type `Map<Symbol, u32>`"),
            "{err}"
        );
        assert_no_debug_output(&err);
    }

    /// The raw `Debug` shapes the error conventions in `commands/mod.rs`
    /// rule out.
    fn assert_no_debug_output(err: &CliError) {
        for marker in ["ScSpecType", " { ", "Box(", "\\\""] {
            assert!(!err.0.contains(marker), "debug output {marker:?} in: {err}");
        }
    }

    #[test]
    fn unsupported_ramp_types_are_named_without_debug_output() {
        let env = Env::default();
        let ty = ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
            value_type: Box::new(vec_of(ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n: 32 }))),
        }));
        let err = ramp_val(&env, &ty, 3).expect_err("not a ramp type");
        assert!(err.0.contains("(`Option<Vec<BytesN<32>>>`)"), "{err}");
        assert_no_debug_output(&err);
    }

    #[test]
    fn monotonicity_sampling_detects_non_monotonic_behavior() {
        let mut probe_calls = Vec::new();
        let mut probe = |values: &[u32]| -> Result<Option<Vec<bool>>, CliError> {
            probe_calls.push(values.to_vec());
            // Return false for value 5 to simulate non-monotonic behavior
            Ok(Some(values.iter().map(|v| *v != 5).collect()))
        };

        // lo=4 (success), hi=10 (failure), sample between them
        let result = sample_monotonicity(4, 10, 3, &mut probe);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "should detect non-monotonic behavior");
    }

    #[test]
    fn monotonicity_sampling_passes_on_monotonic_data() {
        let monotonic_probe = |values: &[u32]| -> Result<Option<Vec<bool>>, CliError> {
            // All values in range are successful
            Ok(Some(values.iter().map(|_| true).collect()))
        };

        let result = sample_monotonicity(1, 100, 5, monotonic_probe);
        assert!(result.is_ok());
        assert!(result.unwrap(), "should pass on monotonic data");
    }

    #[test]
    fn type_names_read_like_rust() {
        let cases = [
            (ScSpecTypeDef::U32, "u32"),
            (ScSpecTypeDef::Bool, "bool"),
            (vec_of(ScSpecTypeDef::Address), "Vec<Address>"),
            (
                ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
                    ok_type: Box::new(ScSpecTypeDef::Void),
                    error_type: Box::new(ScSpecTypeDef::Error),
                })),
                "Result<(), Error>",
            ),
            (
                ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
                    value_types: vec![ScSpecTypeDef::I128, ScSpecTypeDef::Symbol]
                        .try_into()
                        .expect("two types fit"),
                })),
                "(i128, Symbol)",
            ),
            (
                ScSpecTypeDef::Udt(ScSpecTypeUdt {
                    name: "DataKey".try_into().expect("name fits"),
                }),
                "DataKey",
            ),
        ];
        for (ty, expected) in cases {
            assert_eq!(type_name(&ty), expected);
        }
    }

    #[test]
    fn spec_read_failures_name_the_file_and_the_fix() {
        let path = std::path::Path::new("README.md");
        let err = soroban_spec::read::from_wasm(b"not wasm").expect_err("not a wasm module");
        let err = spec_error(path, &err);
        assert!(
            err.0
                .starts_with("`README.md` is not a valid WebAssembly module"),
            "{err}"
        );
        assert!(err.0.contains("wasm32v1-none"), "{err}");
        assert_no_debug_output(&err);

        let err = spec_error(path, &soroban_spec::read::FromWasmError::NotFound);
        assert!(err.0.contains("no contract spec"), "{err}");
    }

    /// Every spec type `limits` can meet, with how it is treated: whether a
    /// non-ramp parameter of that type gets a default, and whether it can be
    /// ramped. This table is the support list `limits --help` documents.
    fn spec_type_table() -> Vec<(ScSpecTypeDef, bool, bool)> {
        let option_u32 = ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        let map = ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::Symbol),
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        vec![
            (ScSpecTypeDef::Val, false, false),
            (ScSpecTypeDef::Bool, true, false),
            (ScSpecTypeDef::Void, false, false),
            (ScSpecTypeDef::Error, false, false),
            (ScSpecTypeDef::U32, true, true),
            (ScSpecTypeDef::I32, true, true),
            (ScSpecTypeDef::U64, true, true),
            (ScSpecTypeDef::I64, true, true),
            (ScSpecTypeDef::Timepoint, false, false),
            (ScSpecTypeDef::Duration, false, false),
            (ScSpecTypeDef::U128, true, true),
            (ScSpecTypeDef::I128, true, true),
            (ScSpecTypeDef::U256, false, false),
            (ScSpecTypeDef::I256, false, false),
            (ScSpecTypeDef::Bytes, true, false),
            (ScSpecTypeDef::String, true, false),
            (ScSpecTypeDef::Symbol, true, false),
            (ScSpecTypeDef::Address, true, false),
            (ScSpecTypeDef::MuxedAddress, false, false),
            (option_u32, true, false),
            (
                ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
                    ok_type: Box::new(ScSpecTypeDef::Void),
                    error_type: Box::new(ScSpecTypeDef::Error),
                })),
                false,
                false,
            ),
            (vec_of(ScSpecTypeDef::Address), true, true),
            (vec_of(ScSpecTypeDef::U32), true, true),
            (vec_of(ScSpecTypeDef::Symbol), true, true),
            (vec_of(ScSpecTypeDef::Bool), true, true),
            (vec_of(ScSpecTypeDef::Bytes), true, true),
            (map, false, false),
            (
                ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
                    value_types: vec![ScSpecTypeDef::I128, ScSpecTypeDef::Symbol]
                        .try_into()
                        .expect("two types fit"),
                })),
                false,
                false,
            ),
            (
                ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n: 32 }),
                false,
                false,
            ),
            (
                ScSpecTypeDef::Udt(ScSpecTypeUdt {
                    name: "DataKey".try_into().expect("name fits"),
                }),
                false,
                false,
            ),
        ]
    }

    #[test]
    fn every_spec_type_defaults_and_ramps_as_documented() {
        let env = Env::default();
        let admin = Address::generate(&env);
        for (ty, can_default, can_ramp) in spec_type_table() {
            let fixture = input("param", ty.clone());
            let defaulted = default_val(&env, &admin, &ty, &fixture, None);
            assert_eq!(defaulted.is_ok(), can_default, "default for {ty:?}");
            if let Err(err) = defaulted {
                assert!(err.0.contains(&quote(type_name(&ty))), "{err}");
                assert_no_debug_output(&err);
            }

            let ramped = ramp_val(&env, &ty, 2);
            assert_eq!(ramped.is_ok(), can_ramp, "ramp for {ty:?}");
            if let Err(err) = ramped {
                assert!(err.0.contains(&quote(type_name(&ty))), "{err}");
                assert_no_debug_output(&err);
            }
        }
    }

    #[test]
    fn vec_ramps_generate_exactly_the_requested_addresses() {
        use soroban_sdk::TryFromVal;

        let env = Env::default();
        let addresses = vec_of(ScSpecTypeDef::Address);
        let decode = |ramp: i64| {
            let val = ramp_val(&env, &addresses, ramp).unwrap();
            SVec::<Address>::try_from_val(&env, &val).unwrap()
        };

        // An empty vector is a valid probe, and it is still a real Vec.
        assert_eq!(decode(0).len(), 0);
        let three = decode(3);
        assert_eq!(three.len(), 3);
        assert_ne!(
            three.get(0),
            three.get(1),
            "each item is a distinct address"
        );

        // The cap is inclusive; one more item is refused before any is generated.
        assert_eq!(
            decode(i64::from(MAX_VEC_RAMP_ITEMS)).len(),
            MAX_VEC_RAMP_ITEMS
        );
        let err = ramp_val(&env, &addresses, i64::from(MAX_VEC_RAMP_ITEMS) + 1)
            .expect_err("above the cap");
        assert!(err.0.contains("at most 1024 items"), "{err}");
        assert_eq!(
            ramp_limits(&addresses).unwrap(),
            (0, i64::from(MAX_VEC_RAMP_ITEMS))
        );
        assert_eq!(
            ramp_limits(&ScSpecTypeDef::U32).unwrap(),
            (0, i64::from(SEARCH_CEILING))
        );
    }

    #[test]
    fn vec_ramps_fill_scalar_elements_with_their_default_value() {
        use soroban_sdk::TryFromVal;

        let env = Env::default();
        let val = ramp_val(&env, &vec_of(ScSpecTypeDef::U32), 4).unwrap();
        let numbers = SVec::<u32>::try_from_val(&env, &val).unwrap();
        assert_eq!(numbers.len(), 4);
        assert!((0..numbers.len()).all(|i| numbers.get(i) == Some(1)));

        // A Vec whose element has no default is refused, even at length 0.
        let map = ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::Symbol),
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        let err = ramp_val(&env, &vec_of(map), 0).expect_err("Map elements cannot be ramped");
        assert!(err.0.contains("`Map<Symbol, u32>`"), "{err}");
        assert_no_debug_output(&err);
    }

    /// Runs the ladder and refinement for `plan` over search indices, where a
    /// ramp value succeeds when `ok` holds, and returns the boundary value.
    fn boundary_value(plan: RampPlan, ceiling: u32, ok: impl Fn(i64) -> bool) -> Option<i64> {
        let mut probe = |indices: &[u32]| -> Result<Option<Vec<bool>>, CliError> {
            Ok(Some(
                indices
                    .iter()
                    .map(|&index| ok(plan.value_at(index)))
                    .collect(),
            ))
        };
        let (last_ok, first_failed) = match find_ladder_bounds(4, ceiling, &mut probe).unwrap() {
            Search::Done(bounds) => bounds,
            Search::Cancelled { .. } => unreachable!("no cancellation in this test"),
        };
        let last_ok = last_ok?;
        let Some(hi) = first_failed else {
            return Some(plan.value_at(last_ok));
        };
        match refine_boundary(last_ok, hi, 4, &mut probe).unwrap() {
            Search::Done(boundary) => Some(plan.value_at(boundary)),
            Search::Cancelled { .. } => unreachable!("no cancellation in this test"),
        }
    }

    #[test]
    fn a_custom_start_probes_from_that_value_and_reports_values() {
        // Values are 40 + index, so successes are the values up to 1000.
        let (plan, ceiling) = ramp_plan(40, 1, &ScSpecTypeDef::U32).unwrap();
        assert_eq!(plan.value_at(0), 40);
        assert_eq!(plan.value_at(4), 44);
        assert_eq!(
            boundary_value(plan, ceiling, |value| value <= 1000),
            Some(1000)
        );
        // A start that already fails leaves no successful value.
        assert_eq!(boundary_value(plan, ceiling, |value| value < 40), None);
    }

    #[test]
    fn a_negative_step_probes_downwards_into_negative_values() {
        // An i32 ramp from 0 stepping by -1 succeeds while the value stays >= -300.
        let (plan, ceiling) = ramp_plan(0, -1, &ScSpecTypeDef::I32).unwrap();
        assert_eq!(plan.value_at(4), -4);
        assert_eq!(
            boundary_value(plan, ceiling, |value| value >= -300),
            Some(-300)
        );
    }

    #[test]
    fn start_and_step_are_checked_against_the_ramp_type() {
        let vec_ramp = vec_of(ScSpecTypeDef::Address);
        let outside = ramp_plan(-1, 1, &ScSpecTypeDef::U32).unwrap_err();
        assert!(
            outside
                .0
                .contains("--start -1 is outside the values a `u32` ramp can take (0 to 16777216)"),
            "{outside}"
        );
        let zero_step = ramp_plan(0, 0, &ScSpecTypeDef::U32).unwrap_err();
        assert!(zero_step.0.contains("--step must not be 0"), "{zero_step}");
        let too_long = ramp_plan(0, 2000, &vec_ramp).unwrap_err();
        assert!(
            too_long.0.contains(
                "--step 2000 is larger than the range of a `Vec<Address>` ramp (0 to 1024)"
            ),
            "{too_long}"
        );
        assert!(ramp_plan(0, 2, &vec_ramp).is_ok());
    }

    #[test]
    fn ramp_values_the_type_cannot_hold_are_refused_with_the_type_named() {
        let env = Env::default();
        let err = ramp_val(&env, &ScSpecTypeDef::U32, -1).expect_err("u32 cannot be negative");
        assert!(
            err.0
                .contains("ramp value -1 is outside the range of `u32`"),
            "{err}"
        );
        assert!(ramp_val(&env, &ScSpecTypeDef::I32, -1).is_ok());
        assert!(ramp_val(&env, &vec_of(ScSpecTypeDef::Address), -1).is_err());
    }

    #[test]
    fn repeat_samples_summarize_with_a_lower_median() {
        let odd = Spread::of(vec![9, 3, 5]);
        assert_eq!((odd.min, odd.median, odd.max, odd.samples), (3, 5, 9, 3));
        assert_eq!(odd.describe(), "5 (median of 3; min 3, max 9)");

        let even = Spread::of(vec![8, 2, 6, 4]);
        assert_eq!((even.min, even.median, even.max), (2, 4, 8));

        // A single measurement is printed as a plain figure.
        assert_eq!(Spread::of(vec![7]).describe(), "7");
    }

    #[test]
    fn repeat_outside_one_to_sixteen_is_rejected_before_loading_the_contract() {
        for repeat in [0, MAX_REPEATS + 1] {
            let args = LimitsArgs {
                contract: "missing.wasm".into(),
                function: "run".into(),
                ramp: "amount".into(),
                start: 0,
                step: 1,
                jobs: 1,
                probe_timeout: 120,
                repeat,
                dry_run: false,
                bool_defaults: Vec::new(),
                auth_mode: AuthMode::All,
                json: false,
            };
            let out = crate::commands::output::Output {
                verbosity: crate::commands::output::Verbosity::Quiet,
                color: false,
            };
            let err = run(args, out).unwrap_err();
            assert_eq!(
                err.0,
                format!("--repeat must be between 1 and 16 (got {repeat})")
            );
        }
    }
}
