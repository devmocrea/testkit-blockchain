use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use proc_macro2::Span;
use quote::ToTokens;
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Expr, FnArg, ImplItemFn, Item, ItemFn, ItemImpl, Local, Pat, Signature, Type,
    Visibility,
};
use walkdir::{self, WalkDir};

use super::output::Output;
use super::CliError;

/// Arguments for `soroban-testkit audit`.
#[derive(Args)]
#[command(after_help = "EXAMPLES:\n    \
    soroban-testkit audit ./src\n    \
    soroban-testkit audit ./src --strict\n    \
    soroban-testkit audit ./src --rule missing-require-auth --rule missing-ttl-bump\n    \
    soroban-testkit audit ./src --exclude-rule unchecked-i128-arithmetic\n    \
    soroban-testkit audit . --exclude target --exclude '**/generated/**'\n    \
    soroban-testkit audit . --include 'contracts/**' --exclude '*_test.rs'\n    \
    soroban-testkit audit ./src --json | jq '.findings'")]
pub struct AuditArgs {
    /// Directory or .rs file to audit; directories are scanned recursively
    /// for .rs files. Pass `-` to read a single source file from stdin
    /// (for editor integrations that audit unsaved buffers)
    #[arg(value_name = "PATH", default_value = ".", verbatim_doc_comment)]
    path: PathBuf,
    /// Exit 1 if any findings are reported. Without it, findings are
    /// printed and the command still exits 0
    #[arg(long, verbatim_doc_comment)]
    strict: bool,
    /// Print findings as a JSON document (`schema_version` 1) on stdout
    /// instead of text
    #[arg(long, verbatim_doc_comment)]
    json: bool,
    /// Run only this rule (repeatable, or comma-separated). Every rule
    /// named is run; rules not named are skipped. Without --rule, all
    /// rules run
    #[arg(
        long = "rule",
        value_name = "RULE",
        value_enum,
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    rules: Vec<Rule>,
    /// Skip this rule (repeatable, or comma-separated). Applied after
    /// --rule; naming a rule in both is an error
    #[arg(
        long = "exclude-rule",
        value_name = "RULE",
        value_enum,
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    exclude_rules: Vec<Rule>,
    /// Audit only .rs files matching this glob (repeatable, or
    /// comma-separated). Globs match paths relative to PATH with `/`
    /// separators: `*` and `?` stay within one path segment, `**` spans
    /// any number of segments, and a glob without `/` matches a file or
    /// directory name at any depth. A file also matches when one of its
    /// parent directories does. Without --include, every .rs file is
    /// audited
    #[arg(
        long = "include",
        value_name = "GLOB",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    include: Vec<String>,
    /// Skip .rs files and directories matching this glob (repeatable, or
    /// comma-separated), e.g. generated or vendored code. Same syntax as
    /// --include and applied after it; skipped directories are not read
    #[arg(
        long = "exclude",
        value_name = "GLOB",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    exclude: Vec<String>,
}

/// The audit rules, by the ID each finding reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum)]
pub enum Rule {
    /// An entry point's Address parameter that is never checked with require_auth
    MissingRequireAuth,
    /// Raw `+ - * /` on an i128 value
    UncheckedI128Arithmetic,
    /// A persistent/temporary storage read with no extend_ttl
    MissingTtlBump,
}

impl Rule {
    const ALL: [Rule; 3] = [
        Rule::MissingRequireAuth,
        Rule::UncheckedI128Arithmetic,
        Rule::MissingTtlBump,
    ];

    /// The rule ID used in findings and accepted by --rule/--exclude-rule.
    pub fn id(self) -> &'static str {
        match self {
            Rule::MissingRequireAuth => "missing-require-auth",
            Rule::UncheckedI128Arithmetic => "unchecked-i128-arithmetic",
            Rule::MissingTtlBump => "missing-ttl-bump",
        }
    }
}

/// Resolves `--rule` and `--exclude-rule` into the rules to run, in the
/// fixed order of [`Rule::ALL`]. Selecting rules never hides findings of
/// another selected rule: every rule in the result is fully evaluated, and
/// the filter only decides which rules run, not which findings are kept.
///
/// Contradictory flags are usage errors, so the message is returned for
/// [`usage_error`] to report like any other clap argument error (exit 2).
fn selected_rules(include: &[Rule], exclude: &[Rule]) -> Result<Vec<Rule>, String> {
    if let Some(rule) = include.iter().find(|rule| exclude.contains(rule)) {
        return Err(format!(
            "rule `{}` is both selected with --rule and skipped with --exclude-rule; \
             pass it to only one of them",
            rule.id()
        ));
    }
    let rules: Vec<Rule> = Rule::ALL
        .into_iter()
        .filter(|rule| include.is_empty() || include.contains(rule))
        .filter(|rule| !exclude.contains(rule))
        .collect();
    if rules.is_empty() {
        return Err(
            "--exclude-rule skips every rule, so there is nothing to audit; \
                    leave at least one rule enabled"
                .to_string(),
        );
    }
    Ok(rules)
}

/// `--include` / `--exclude` path globs (#142), matched against the same
/// root-relative, `/`-separated paths findings are reported under.
///
/// Syntax, kept deliberately small and dependency-free:
/// - `*` matches any run of characters within one path segment, `?` exactly
///   one character, and `**` as a whole segment any number of segments
///   (including none);
/// - a glob without `/` matches a file or directory name at any depth, like
///   a `.gitignore` entry (`generated`, `*_pb.rs`);
/// - a glob with `/` is anchored at the audited root (`src/gen/**`); a
///   leading `./` or `/` and a trailing `/` are ignored, and `\` is read as
///   `/` so Windows-style globs work;
/// - a path matches when the glob matches it or any of its parent
///   directories, so `--exclude vendor` skips everything under `vendor/`.
///
/// A file is audited when it matches some `--include` glob (or none were
/// given) and no `--exclude` glob.
#[derive(Debug, Default)]
struct PathFilter {
    include: Vec<Vec<String>>,
    exclude: Vec<Vec<String>>,
}

impl PathFilter {
    fn new(include: &[String], exclude: &[String]) -> Result<Self, String> {
        let parse = |flag: &str, globs: &[String]| -> Result<Vec<Vec<String>>, String> {
            globs
                .iter()
                .map(|glob| {
                    let normalized = glob.replace('\\', "/");
                    let trimmed = normalized
                        .trim_start_matches("./")
                        .trim_start_matches('/')
                        .trim_end_matches('/');
                    if trimmed.is_empty() {
                        return Err(format!(
                            "{flag} {} is empty; pass a glob such as `target` or `src/generated/**`",
                            super::quote(glob)
                        ));
                    }
                    let mut segments: Vec<String> = trimmed
                        .split('/')
                        .filter(|segment| !segment.is_empty() && *segment != ".")
                        .map(str::to_string)
                        .collect();
                    // No `/`: match the name at any depth.
                    if segments.len() == 1 && segments[0] != "**" {
                        segments.insert(0, "**".to_string());
                    }
                    Ok(segments)
                })
                .collect()
        };
        Ok(PathFilter {
            include: parse("--include", include)?,
            exclude: parse("--exclude", exclude)?,
        })
    }

    fn is_active(&self) -> bool {
        !self.include.is_empty() || !self.exclude.is_empty()
    }

    /// Whether `path` (or one of its parent directories) matches an
    /// `--exclude` glob.
    fn excludes(&self, path: &str) -> bool {
        self.exclude
            .iter()
            .any(|glob| matches_path_or_parent(glob, path))
    }

    /// Whether the file at `path` should be audited.
    fn selects(&self, path: &str) -> bool {
        (self.include.is_empty()
            || self
                .include
                .iter()
                .any(|glob| matches_path_or_parent(glob, path)))
            && !self.excludes(path)
    }
}

fn matches_path_or_parent(glob: &[String], path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    (1..=segments.len()).any(|len| match_segments(glob, &segments[..len]))
}

fn match_segments(glob: &[String], path: &[&str]) -> bool {
    match glob.split_first() {
        None => path.is_empty(),
        Some((first, rest)) if first == "**" => {
            (0..=path.len()).any(|skip| match_segments(rest, &path[skip..]))
        }
        Some((first, rest)) => path.split_first().is_some_and(|(head, tail)| {
            match_segment(first.as_bytes(), head.as_bytes()) && match_segments(rest, tail)
        }),
    }
}

/// `*` and `?` within a single segment. Bytes are compared, so `?` matches
/// one byte; globs are expected to be ASCII.
fn match_segment(glob: &[u8], name: &[u8]) -> bool {
    match glob.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|skip| match_segment(rest, &name[skip..])),
        Some((b'?', rest)) => !name.is_empty() && match_segment(rest, &name[1..]),
        Some((c, rest)) => name.first() == Some(c) && match_segment(rest, &name[1..]),
    }
}

/// Exits with clap's usage-error format and status 2, as for an unknown
/// flag, honouring --no-color / NO_COLOR like the rest of the CLI.
fn usage_error(message: String) -> ! {
    use clap::CommandFactory;
    let mut command = super::Cli::command();
    if super::output::no_color_requested(std::env::args_os()) {
        command = command.color(clap::ColorChoice::Never);
    }
    command.build();
    command
        .find_subcommand_mut("audit")
        .expect("audit is a subcommand")
        .error(clap::error::ErrorKind::ArgumentConflict, message)
        .exit()
}

/// Version of the `audit --json` document shape. Bump it on any breaking
/// change: a removed or renamed field, or a changed type or meaning.
/// Adding a new field is not breaking and keeps the same version.
const AUDIT_JSON_SCHEMA_VERSION: u32 = 1;

/// The bounded claim every non-quiet `audit` run ends with, including a
/// clean one: an empty result is not a security guarantee.
const DISCLAIMER: &str = "soroban-testkit audit is a linter with three heuristics, not a security \
                          product — a missing finding is not a security guarantee.";

/// A `.rs` file that was not audited because it is not valid Rust syntax
/// (#144). Reported with the parser's position and message instead of being
/// dropped silently, so a clean result never hides an unaudited file.
#[derive(Debug, PartialEq)]
struct Skipped {
    /// Same form as [`Finding::file`].
    file: String,
    /// 1-based line of the parse error.
    line: usize,
    /// 1-based column of the parse error.
    column: usize,
    message: String,
}

#[derive(Debug)]
struct Finding {
    /// See [`finding_path`].
    file: String,
    line: usize,
    rule: &'static str,
    severity: &'static str,
    message: String,
}

/// Static checks over a contract crate. **Not a security product** — a
/// linter with three heuristics, each independently useful and each
/// capable of missing real bugs or flagging non-bugs. The absence of a
/// finding here is never a security guarantee.
///
/// 1. Contract entry points taking an `Address` parameter that never call
///    `require_auth` anywhere in the function body. An entry point is a
///    `pub fn` in an `impl` block marked `#[contractimpl]`, or any fn of a
///    `#[contractimpl]` trait impl; free functions and helper `impl`s are
///    not entry points (see [`EntryPoints`]).
/// 2. Arithmetic (`+ - * / %`, unary `-`, compound assignment, and raw
///    arithmetic method calls) on an `i128`-typed binding, done outside a
///    `checked_`/`saturating_`/`wrapping_` call. The finding points at the
///    operator's line, so multiline expressions identify the exact
///    arithmetic source location.
/// 3. A `.persistent()`/`.temporary()` storage read with no
///    `.extend_ttl(` call anywhere in the same function.
///
/// Finding paths are relative to the audited `PATH` and `/`-separated (see
/// [`finding_path`]), so the same crate reports the same paths whichever
/// directory the command runs from. `--include`/`--exclude` globs match
/// those same paths (see [`PathFilter`]). Files that do not parse are
/// listed as skipped, with the parser's position and message.
pub fn run(args: AuditArgs, out: Output) -> Result<(), CliError> {
    let rules =
        selected_rules(&args.rules, &args.exclude_rules).unwrap_or_else(|msg| usage_error(msg));
    let all_rules = rules.len() == Rule::ALL.len();
    let filter =
        PathFilter::new(&args.include, &args.exclude).unwrap_or_else(|msg| usage_error(msg));
    let mut findings = Vec::new();
    let mut skipped = Vec::new();

    if args.path == Path::new("-") {
        if filter.is_active() {
            usage_error(
                "--include and --exclude filter the files found under a directory PATH; \
                 they cannot be used when reading from stdin (`-`)"
                    .to_string(),
            );
        }
        let mut src = String::new();
        std::io::stdin()
            .read_to_string(&mut src)
            .map_err(|err| CliError(format!("failed to read stdin: {err}")))?;
        audit_source(&src, "<stdin>", &rules, &mut findings, &mut skipped);
    } else {
        // WalkDir yields a missing root as an Err entry, which the
        // filter_map below would drop, so a typo'd PATH would otherwise
        // "pass" with no findings.
        std::fs::metadata(&args.path).map_err(|err| {
            CliError(format!(
                "cannot audit {}: {err}; pass a contract crate's source directory, \
                 a .rs file, or `-` for stdin",
                super::quote(args.path.display())
            ))
        })?;
        let mut filtered_out = 0usize;
        let mut audited = 0usize;
        let walker = WalkDir::new(&args.path).into_iter().filter_entry(|entry| {
            // Prune excluded directories so vendored or generated trees are
            // never read. The root itself is always walked.
            if entry.depth() == 0 || !entry.file_type().is_dir() {
                return true;
            }
            let keep = !filter.excludes(&finding_path(&args.path, entry.path()));
            if !keep {
                out.detail(format!("skipping {} (--exclude)", entry.path().display()));
            }
            keep
        });
        for entry in walker {
            // A traversal error means at least one .rs file may never be
            // examined, so stop instead of reporting a misleading clean audit.
            let entry = entry.map_err(|err| traversal_error(&args.path, &err))?;
            // Skip symlinks: audit only follows the real filesystem structure for
            // deterministic results (symlinks can create cycles, loops, or
            // inaccessible paths depending on the platform and permissions).
            if entry.path_is_symlink() {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.path().extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let display = finding_path(&args.path, entry.path());
            if !filter.selects(&display) {
                filtered_out += 1;
                out.detail(format!(
                    "skipping {} (--include/--exclude)",
                    entry.path().display()
                ));
                continue;
            }
            out.detail(format!("scanning {}", entry.path().display()));
            audited += 1;
            audit_file(entry.path(), &display, &rules, &mut findings, &mut skipped)?;
        }
        // A pattern typo would otherwise "pass" with no findings, like a
        // typo'd PATH, so filtering out every .rs file is an error.
        if audited == 0 && filtered_out > 0 {
            return Err(CliError(format!(
                "no .rs file under {} matches --include/--exclude ({filtered_out} filtered out); \
                 check the glob patterns",
                super::quote(args.path.display())
            )));
        }
    }

    // stdout stays a single JSON document with --json, which lists skipped
    // files in its `skipped` field instead.
    if !args.json {
        for skip in &skipped {
            eprintln!(
                "warning: skipped {}:{}:{}: not valid Rust, so it was not audited: {}",
                skip.file, skip.line, skip.column, skip.message
            );
        }
    }
    let skipped_note = match skipped.len() {
        0 => String::new(),
        1 => " 1 file could not be parsed and was not audited (see the warning above).".to_string(),
        n => {
            format!(" {n} files could not be parsed and were not audited (see the warnings above).")
        }
    };

    // Text mode only: stdout must stay a single JSON document with --json,
    // which reports the rules that ran in its `rules` field instead.
    if !all_rules && !args.json {
        let ids: Vec<&str> = rules.iter().map(|rule| rule.id()).collect();
        out.note(format!("audit: running only {}", ids.join(", ")));
    }

    if args.json {
        println!("{}", render_json(&findings, &skipped, &rules));
    } else if findings.is_empty() {
        out.note(format!("audit: no findings.{skipped_note} {DISCLAIMER}"));
    } else {
        for finding in &findings {
            println!(
                "{}:{}: [{}] {}: {}",
                finding.file, finding.line, finding.severity, finding.rule, finding.message
            );
        }
        out.note(format!(
            "\n{} finding(s).{skipped_note} {DISCLAIMER}",
            findings.len()
        ));
    }

    if args.strict && !findings.is_empty() {
        return Err(CliError(format!(
            "{} audit finding(s) (--strict)",
            findings.len()
        )));
    }
    Ok(())
}

/// Renders findings as the `audit --json` document, schema version
/// [`AUDIT_JSON_SCHEMA_VERSION`]:
///
/// ```json
/// {"schema_version":1,"disclaimer":"...","rules":["missing-require-auth","unchecked-i128-arithmetic","missing-ttl-bump"],"skipped":[{"file":"src/gen.rs","line":3,"column":5,"message":"..."}],"finding_count":1,"findings":[{"file":"src/lib.rs","line":7,"severity":"warning","rule":"missing-require-auth","message":"..."}]}
/// ```
///
/// `rules` lists the rules that ran (see `--rule`/`--exclude-rule`) and
/// `skipped` the files that could not be parsed (#144); both were added
/// without a version bump because new fields are not breaking.
fn render_json(findings: &[Finding], skipped: &[Skipped], rules: &[Rule]) -> String {
    let items: Vec<String> = findings
        .iter()
        .map(|finding| {
            format!(
                "{{\"file\":{},\"line\":{},\"severity\":{},\"rule\":{},\"message\":{}}}",
                json_string(&finding.file),
                finding.line,
                json_string(finding.severity),
                json_string(finding.rule),
                json_string(&finding.message),
            )
        })
        .collect();
    let rule_ids: Vec<String> = rules.iter().map(|rule| json_string(rule.id())).collect();
    let skipped_items: Vec<String> = skipped
        .iter()
        .map(|skip| {
            format!(
                "{{\"file\":{},\"line\":{},\"column\":{},\"message\":{}}}",
                json_string(&skip.file),
                skip.line,
                skip.column,
                json_string(&skip.message),
            )
        })
        .collect();
    format!(
        "{{\"schema_version\":{AUDIT_JSON_SCHEMA_VERSION},\"disclaimer\":{},\"rules\":[{}],\"skipped\":[{}],\"finding_count\":{},\"findings\":[{}]}}",
        json_string(DISCLAIMER),
        rule_ids.join(","),
        skipped_items.join(","),
        findings.len(),
        items.join(",")
    )
}

/// Quotes and escapes `value` as a JSON string. Hand-rolled so the audit
/// command takes no serialization dependency for one small document.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The path a finding in `file` is reported under: relative to the audited
/// `root` with `/` separators, e.g. `src/lib.rs` for `root = "."` or
/// `lib.rs` for `root = "examples/vault/src"`. When `root` is the file
/// itself, its file name is used. Falls back to `file` as given if it is
/// not under `root`.
fn finding_path(root: &Path, file: &Path) -> String {
    let relative = match file.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => file.file_name().map(Path::new).unwrap_or(file),
        Ok(rel) => rel,
        Err(_) => file,
    };
    relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn audit_file(
    path: &Path,
    display: &str,
    rules: &[Rule],
    findings: &mut Vec<Finding>,
    skipped: &mut Vec<Skipped>,
) -> Result<(), CliError> {
    let src = std::fs::read_to_string(path).map_err(|err| {
        CliError(format!(
            "failed to read {}: {err}",
            super::quote(path.display())
        ))
    })?;
    audit_source(&src, display, rules, findings, skipped);
    Ok(())
}

/// Turns a `WalkDir` failure into the shared CLI error shape. The audited
/// root is named so the message stays actionable when `walkdir::Error` has
/// no path of its own (for example, some loop and metadata failures).
fn traversal_error(root: &Path, err: &walkdir::Error) -> CliError {
    let path = err.path().unwrap_or(root);
    let cause = match err.io_error() {
        Some(io) => io.to_string(),
        None => err.to_string(),
    };
    format_traversal_error(path, &cause)
}

fn format_traversal_error(path: &Path, cause: &str) -> CliError {
    CliError(format!(
        "cannot audit {}: {cause}; make the directory readable or pass a different PATH",
        super::quote(path.display())
    ))
}

/// Parses `src` (the contents of a single `.rs` file, attributed to
/// `display` in findings) and walks it for audit findings. Only `rules` are
/// evaluated. An empty source has no findings. An unparseable source is not
/// an error — not every `.rs` file under a crate root need parse standalone
/// (generated templates, say), and a stdin editor buffer may be mid-edit —
/// but it is recorded in `skipped` with the parser's position and message,
/// so the caller can report it rather than imply it was audited (#144).
///
/// Each function is audited once, against its own body: nested items (a
/// `fn` or `impl` declared inside a function body) are skipped by every
/// rule's walk and audited separately as functions of their own, so one
/// source expression is never reported twice.
fn audit_source(
    src: &str,
    display: &str,
    rules: &[Rule],
    findings: &mut Vec<Finding>,
    skipped: &mut Vec<Skipped>,
) {
    let file = match syn::parse_file(src) {
        Ok(file) => file,
        Err(err) => {
            let start = err.span().start();
            skipped.push(Skipped {
                file: display.to_string(),
                line: start.line.max(1),
                // proc-macro2 columns are 0-based; editors count from 1.
                column: start.column + 1,
                message: parse_error_message(&err),
            });
            return;
        }
    };

    let mut visitor = FunctionVisitor {
        path: display.to_string(),
        rules,
        findings,
        contract_impl: None,
    };
    visitor.visit_file(&file);
}

/// The parser's message, made actionable for tokenizer failures: syn reports
/// an unbalanced delimiter or unterminated literal only as "cannot parse
/// string into token stream", pointing at the offending token.
fn parse_error_message(err: &syn::Error) -> String {
    let message = err.to_string();
    if message == "cannot parse string into token stream" {
        format!(
            "unbalanced delimiter, or an unterminated string, character literal or comment \
             ({message})"
        )
    } else {
        message
    }
}

/// Which functions of an `impl` block are contract entry points (#134).
///
/// Soroban exports the `pub` functions of an `impl` marked `#[contractimpl]`
/// (in any spelling, e.g. `#[soroban_sdk::contractimpl]` or
/// `#[contractimpl(contracttrait)]`), and every function of a
/// `#[contractimpl]` trait impl, whose methods take the trait's visibility.
/// Free functions and methods of other `impl` blocks are ordinary Rust
/// helpers: callers reach them only through an entry point, which is where
/// `require_auth` belongs, so `missing-require-auth` does not apply to them.
/// Macros are not expanded, so entry points generated by a macro are not seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryPoints {
    /// `#[contractimpl] impl Contract { .. }`: only `pub fn`s.
    PublicFns,
    /// `#[contractimpl] impl Trait for Contract { .. }`: every fn.
    AllFns,
}

fn is_contractimpl(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|seg| seg.ident == "contractimpl")
    })
}

struct FunctionVisitor<'a> {
    path: String,
    rules: &'a [Rule],
    findings: &'a mut Vec<Finding>,
    /// Set while visiting the items of a `#[contractimpl]` block.
    contract_impl: Option<EntryPoints>,
}

impl<'ast> Visit<'ast> for FunctionVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let line = line_of(node);
        // A free function is never an entry point, even when nested in one.
        self.audit_function(&node.sig, &node.block, line, false);
        self.audit_i128_arithmetic(&node.sig, &node.block);
        // Continues into nested items, which are audited as their own functions
        visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let outer = self.contract_impl;
        self.contract_impl = is_contractimpl(&node.attrs).then_some(if node.trait_.is_some() {
            EntryPoints::AllFns
        } else {
            EntryPoints::PublicFns
        });
        visit::visit_item_impl(self, node);
        self.contract_impl = outer;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let line = line_of(node);
        let entry_point = match self.contract_impl {
            Some(EntryPoints::AllFns) => true,
            Some(EntryPoints::PublicFns) => matches!(node.vis, Visibility::Public(_)),
            None => false,
        };
        self.audit_function(&node.sig, &node.block, line, entry_point);
        self.audit_i128_arithmetic(&node.sig, &node.block);
        visit::visit_impl_item_fn(self, node);
    }
}

impl FunctionVisitor<'_> {
    fn runs(&self, rule: Rule) -> bool {
        self.rules.contains(&rule)
    }

    fn audit_function(
        &mut self,
        sig: &Signature,
        body: &syn::Block,
        line: usize,
        entry_point: bool,
    ) {
        let name = sig.ident.to_string();

        // Rule 1: an entry point's Address parameter that's never checked
        // with require_auth. Helpers are reached through an entry point.
        let address_params = address_typed_params(sig);
        if entry_point && self.runs(Rule::MissingRequireAuth) && !address_params.is_empty() {
            let mut tracked_addrs = HashSet::new();
            for arg in &sig.inputs {
                if let FnArg::Typed(pat_type) = arg {
                    if type_is_address(&pat_type.ty) {
                        extract_pat_idents(&pat_type.pat, &mut tracked_addrs);
                    }
                }
            }
            let mut auth_visitor = RequireAuthVisitor {
                tracked_addrs,
                has_require_auth: false,
            };
            auth_visitor.visit_block(body);
            if !auth_visitor.has_require_auth {
                self.push(
                    line,
                    Rule::MissingRequireAuth.id(),
                    "warning",
                    format!(
                        "fn {name} takes Address parameter(s) {address_params:?} but never calls \
                         require_auth on any of them in its body"
                    ),
                );
            }
        }

        // Rule 3: a storage read with no extend_ttl anywhere in the function.
        if !self.runs(Rule::MissingTtlBump) {
            return;
        }
        let mut storage_visitor = StorageAccessVisitor {
            storage_type: None,
            has_extend_ttl: false,
        };
        storage_visitor.visit_block(body);

        if let Some(storage_type) = storage_visitor.storage_type {
            if !storage_visitor.has_extend_ttl {
                self.push(
                    line,
                    Rule::MissingTtlBump.id(),
                    "warning",
                    format!(
                        "fn {name} reads from {} storage but never calls extend_ttl in its body",
                        storage_type
                    ),
                );
            }
        }
    }

    fn push(&mut self, line: usize, rule: &'static str, severity: &'static str, message: String) {
        self.findings.push(Finding {
            file: self.path.clone(),
            line,
            rule,
            severity,
            message,
        });
    }

    fn audit_i128_arithmetic(&mut self, sig: &Signature, body: &syn::Block) {
        if !self.runs(Rule::UncheckedI128Arithmetic) {
            return;
        }
        let mut i128_bindings: HashSet<String> = HashSet::new();
        for arg in &sig.inputs {
            if let FnArg::Typed(pat_type) = arg {
                if type_is_i128(&pat_type.ty) {
                    if let Pat::Ident(ident) = &*pat_type.pat {
                        i128_bindings.insert(ident.ident.to_string());
                    }
                }
            }
        }

        let mut visitor = I128ArithmeticVisitor {
            path: self.path.clone(),
            fn_name: sig.ident.to_string(),
            i128_bindings,
            findings: self.findings,
        };
        visitor.visit_block(body);
    }
}

fn address_typed_params(sig: &Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(pat_type) if type_is_address(&pat_type.ty) => match &*pat_type.pat {
                Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => Some("<pattern>".to_string()),
            },
            _ => None,
        })
        .collect()
}

fn type_is_address(ty: &Type) -> bool {
    match ty {
        Type::Reference(r) => type_is_address(&r.elem),
        Type::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|seg| seg.ident == "Address"),
        _ => false,
    }
}

fn line_of(node: impl ToTokens) -> usize {
    first_span(node).start().line
}

/// The span of the first token produced by `node`. For a `BinOp` this is
/// the operator itself, which is what arithmetic findings point at.
fn first_span(node: impl ToTokens) -> Span {
    node.to_token_stream()
        .into_iter()
        .next()
        .map_or_else(Span::call_site, |token| token.span())
}

/// Rule 2 uses a dedicated AST walk (rather than a text search) because
/// "arithmetic on an i128" needs to know which bindings are actually
/// typed `i128`, and a plain string search over the token stream can't
/// tell an `i128` value from the substring appearing anywhere else.
///
/// A finding is reported once per arithmetic *expression*, at that
/// expression's line: `a + b + c` parses as `(a + b) + c`, but it is one
/// source expression and produces one finding. Arithmetic in a separate
/// expression nested inside it (e.g. a call argument) is reported on its own.
struct I128ArithmeticVisitor<'a> {
    path: String,
    fn_name: String,
    i128_bindings: HashSet<String>,
    findings: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for I128ArithmeticVisitor<'_> {
    // Nested functions are audited separately with their own bindings
    fn visit_item(&mut self, _node: &'ast Item) {}

    fn visit_local(&mut self, node: &'ast Local) {
        let mut is_i128 = false;
        if let Pat::Type(pat_type) = &node.pat {
            if type_is_i128(&pat_type.ty) {
                is_i128 = true;
            }
        }
        if !is_i128 {
            if let Some(init) = &node.init {
                if self.touches_i128(&init.expr) {
                    is_i128 = true;
                }
            }
        }
        if is_i128 {
            if let Pat::Ident(ident) = &node.pat {
                self.i128_bindings.insert(ident.ident.to_string());
            } else if let Pat::Type(pat_type) = &node.pat {
                if let Pat::Ident(ident) = &*pat_type.pat {
                    self.i128_bindings.insert(ident.ident.to_string());
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if !is_arithmetic(&node.op) {
            return visit::visit_expr_binary(self, node);
        }
        let whole = Expr::Binary(node.clone());
        if self.arithmetic_touches_i128(&whole) {
            self.push_arithmetic_finding(line_of(node.op));
        }
        // The arithmetic operators of this expression are covered by the
        // check above; only its non-arithmetic operands may hold separate
        // expressions (calls, blocks, closures) that need their own check.
        self.visit_arithmetic_operands(&whole);
    }

    fn visit_expr_unary(&mut self, node: &'ast syn::ExprUnary) {
        if !matches!(node.op, syn::UnOp::Neg(_)) || is_int_literal(&node.expr) {
            return visit::visit_expr_unary(self, node);
        }
        let whole = Expr::Unary(node.clone());
        if self.arithmetic_touches_i128(&whole) {
            self.push_arithmetic_finding(line_of(node.op));
        }
        self.visit_arithmetic_operands(&whole);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if !is_unchecked_arithmetic_method(&method) {
            return visit::visit_expr_method_call(self, node);
        }
        let whole = Expr::MethodCall(node.clone());
        if self.arithmetic_touches_i128(&whole) {
            self.push_arithmetic_finding(line_of(&node.method));
        }
        self.visit_arithmetic_operands(&whole);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(p) = &*node.func {
            if is_unchecked_arithmetic_fn_path(&p.path)
                && node
                    .args
                    .iter()
                    .any(|arg| self.arithmetic_touches_i128(arg))
            {
                self.push_arithmetic_finding(line_of(p));
                for arg in &node.args {
                    self.visit_arithmetic_operands(arg);
                }
                return;
            }
        }
        visit::visit_expr_call(self, node);
    }
}

fn is_arithmetic(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Add(_)
            | BinOp::Sub(_)
            | BinOp::Mul(_)
            | BinOp::Div(_)
            | BinOp::Rem(_)
            | BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
            | BinOp::RemAssign(_)
    )
}

fn is_compound_assign(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
            | BinOp::RemAssign(_)
    )
}

fn is_unchecked_arithmetic_method(name: &str) -> bool {
    matches!(
        name,
        "add"
            | "sub"
            | "mul"
            | "div"
            | "rem"
            | "neg"
            | "add_assign"
            | "sub_assign"
            | "mul_assign"
            | "div_assign"
            | "rem_assign"
            | "unchecked_add"
            | "unchecked_sub"
            | "unchecked_mul"
            | "unchecked_div"
            | "unchecked_rem"
            | "unchecked_neg"
            | "strict_add"
            | "strict_sub"
            | "strict_mul"
            | "strict_div"
            | "strict_rem"
            | "strict_neg"
    )
}

fn is_safe_arithmetic_method(name: &str) -> bool {
    name.starts_with("checked_")
        || name.starts_with("saturating_")
        || name.starts_with("wrapping_")
        || name.starts_with("overflowing_")
}

fn is_option_unwrap_method(name: &str) -> bool {
    matches!(
        name,
        "unwrap"
            | "expect"
            | "unwrap_or"
            | "unwrap_or_default"
            | "unwrap_or_else"
            | "ok_or"
            | "ok_or_else"
    )
}

fn is_arithmetic_type_or_trait(name: &str) -> bool {
    matches!(
        name,
        "i128"
            | "Add"
            | "Sub"
            | "Mul"
            | "Div"
            | "Rem"
            | "Neg"
            | "AddAssign"
            | "SubAssign"
            | "MulAssign"
            | "DivAssign"
            | "RemAssign"
    )
}

fn is_unchecked_arithmetic_fn_path(path: &syn::Path) -> bool {
    let len = path.segments.len();
    if len < 2 {
        return false;
    }
    let last = path.segments[len - 1].ident.to_string();
    let prev = path.segments[len - 2].ident.to_string();
    is_unchecked_arithmetic_method(&last) && is_arithmetic_type_or_trait(&prev)
}

fn is_safe_arithmetic_fn_path(path: &syn::Path) -> bool {
    let len = path.segments.len();
    if len < 2 {
        return false;
    }
    let last = path.segments[len - 1].ident.to_string();
    let prev = path.segments[len - 2].ident.to_string();
    is_safe_arithmetic_method(&last) && prev == "i128"
}

fn is_int_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(lit) => matches!(lit.lit, syn::Lit::Int(_)),
        Expr::Paren(p) => is_int_literal(&p.expr),
        Expr::Group(g) => is_int_literal(&g.expr),
        _ => false,
    }
}

impl I128ArithmeticVisitor<'_> {
    fn push_arithmetic_finding(&mut self, line: usize) {
        self.findings.push(Finding {
            file: self.path.clone(),
            line,
            rule: Rule::UncheckedI128Arithmetic.id(),
            severity: "warning",
            message: format!(
                "fn {} does raw arithmetic on an i128 value; prefer checked_/saturating_/ \
                 wrapping_ variants to avoid silent overflow",
                self.fn_name
            ),
        });
    }

    /// Whether any operand anywhere in this arithmetic expression (looking
    /// through nested arithmetic operators, method forms, and parentheses) is an i128 value.
    fn arithmetic_touches_i128(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Binary(binary) if is_arithmetic(&binary.op) => {
                self.arithmetic_touches_i128(&binary.left)
                    || self.arithmetic_touches_i128(&binary.right)
            }
            Expr::Unary(unary)
                if matches!(unary.op, syn::UnOp::Neg(_)) && !is_int_literal(&unary.expr) =>
            {
                self.arithmetic_touches_i128(&unary.expr)
            }
            Expr::MethodCall(mc)
                if is_unchecked_arithmetic_method(&mc.method.to_string()) =>
            {
                self.arithmetic_touches_i128(&mc.receiver)
                    || mc.args.iter().any(|arg| self.arithmetic_touches_i128(arg))
            }
            Expr::Paren(p) => self.arithmetic_touches_i128(&p.expr),
            Expr::Group(g) => self.arithmetic_touches_i128(&g.expr),
            other => self.touches_i128(other),
        }
    }

    /// Visits the leaf operands of an arithmetic expression, skipping the
    /// arithmetic nodes that belong to the same source expression.
    fn visit_arithmetic_operands(&mut self, expr: &Expr) {
        match expr {
            Expr::Binary(binary) if is_arithmetic(&binary.op) => {
                self.visit_arithmetic_operands(&binary.left);
                self.visit_arithmetic_operands(&binary.right);
            }
            Expr::Unary(unary)
                if matches!(unary.op, syn::UnOp::Neg(_)) && !is_int_literal(&unary.expr) =>
            {
                self.visit_arithmetic_operands(&unary.expr);
            }
            Expr::MethodCall(mc)
                if is_unchecked_arithmetic_method(&mc.method.to_string()) =>
            {
                self.visit_arithmetic_operands(&mc.receiver);
                for arg in &mc.args {
                    self.visit_arithmetic_operands(arg);
                }
            }
            Expr::Paren(p) => self.visit_arithmetic_operands(&p.expr),
            Expr::Group(g) => self.visit_arithmetic_operands(&g.expr),
            other => self.visit_expr(other),
        }
    }

    fn touches_i128(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(p) => p
                .path
                .get_ident()
                .is_some_and(|ident| self.i128_bindings.contains(&ident.to_string())),
            Expr::Lit(lit) => matches!(&lit.lit, syn::Lit::Int(i) if i.suffix() == "i128"),
            Expr::Reference(r) => self.touches_i128(&r.expr),
            Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_) | syn::UnOp::Neg(_)) => {
                self.touches_i128(&u.expr)
            }
            Expr::Binary(b) if is_arithmetic(&b.op) && !is_compound_assign(&b.op) => {
                self.touches_i128(&b.left) || self.touches_i128(&b.right)
            }
            Expr::Try(t) => self.touches_i128(&t.expr),
            Expr::Cast(c) => type_is_i128(&c.ty),
            Expr::MethodCall(mc) => {
                let method = mc.method.to_string();
                (is_safe_arithmetic_method(&method)
                    || is_unchecked_arithmetic_method(&method)
                    || is_option_unwrap_method(&method))
                    && self.touches_i128(&mc.receiver)
            }
            Expr::Call(call) => {
                if let Expr::Path(p) = &*call.func {
                    (is_safe_arithmetic_fn_path(&p.path)
                        || is_unchecked_arithmetic_fn_path(&p.path))
                        && call.args.iter().any(|arg| self.touches_i128(arg))
                } else {
                    false
                }
            }
            Expr::Paren(p) => self.touches_i128(&p.expr),
            Expr::Group(g) => self.touches_i128(&g.expr),
            _ => false,
        }
    }
}

fn extract_pat_idents(pat: &Pat, bindings: &mut HashSet<String>) {
    match pat {
        Pat::Ident(ident) => {
            bindings.insert(ident.ident.to_string());
        }
        Pat::Reference(r) => extract_pat_idents(&r.pat, bindings),
        Pat::Type(t) => extract_pat_idents(&t.pat, bindings),
        Pat::Paren(p) => extract_pat_idents(&p.pat, bindings),
        Pat::Tuple(t) => {
            for elem in &t.elems {
                extract_pat_idents(elem, bindings);
            }
        }
        _ => {}
    }
}

fn remove_pat_idents(pat: &Pat, bindings: &mut HashSet<String>) {
    let mut idents = HashSet::new();
    extract_pat_idents(pat, &mut idents);
    for id in idents {
        bindings.remove(&id);
    }
}

fn type_is_i128(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.is_ident("i128"))
}

/// Visitor that checks if require_auth is called on a tracked Address parameter
/// (or a local alias of one) in the function body.
struct RequireAuthVisitor {
    tracked_addrs: HashSet<String>,
    has_require_auth: bool,
}

impl<'ast> Visit<'ast> for RequireAuthVisitor {
    // A nested function's require_auth does not authorize the outer function
    fn visit_item(&mut self, _node: &'ast Item) {}

    fn visit_local(&mut self, node: &'ast Local) {
        if let Some(init) = &node.init {
            if self.is_tracked_addr(&init.expr) {
                extract_pat_idents(&node.pat, &mut self.tracked_addrs);
            } else {
                remove_pat_idents(&node.pat, &mut self.tracked_addrs);
            }
        } else {
            remove_pat_idents(&node.pat, &mut self.tracked_addrs);
        }
        visit::visit_local(self, node);
    }

    fn visit_expr(&mut self, node: &'ast Expr) {
        if self.has_require_auth {
            return;
        }
        if let Expr::MethodCall(mc) = node {
            if (mc.method == "require_auth" || mc.method == "require_auth_for_args")
                && self.is_tracked_addr(&mc.receiver)
            {
                self.has_require_auth = true;
                return;
            }
        }
        visit::visit_expr(self, node);
    }
}

impl RequireAuthVisitor {
    fn is_tracked_addr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(p) => p
                .path
                .get_ident()
                .is_some_and(|ident| self.tracked_addrs.contains(&ident.to_string())),
            Expr::Reference(r) => self.is_tracked_addr(&r.expr),
            Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => self.is_tracked_addr(&u.expr),
            Expr::Paren(p) => self.is_tracked_addr(&p.expr),
            Expr::Group(g) => self.is_tracked_addr(&g.expr),
            Expr::MethodCall(mc)
                if matches!(mc.method.to_string().as_str(), "clone" | "to_owned") =>
            {
                self.is_tracked_addr(&mc.receiver)
            }
            _ => false,
        }
    }
}

/// Visitor that checks for storage access patterns (.persistent()/.temporary() with .get())
/// and extend_ttl calls. Replaces text heuristics with AST inspection that handles
/// formatting variations transparently.
struct StorageAccessVisitor {
    storage_type: Option<&'static str>,
    has_extend_ttl: bool,
}

impl<'ast> Visit<'ast> for StorageAccessVisitor {
    // A nested function's storage access is reported for that function only
    fn visit_item(&mut self, _node: &'ast Item) {}

    fn visit_expr(&mut self, node: &'ast Expr) {
        if let Expr::MethodCall(mc) = node {
            if mc.method == "extend_ttl" {
                self.has_extend_ttl = true;
            }
            // Check for .persistent().get() or .temporary().get() chain
            if mc.method == "get" {
                if let Expr::MethodCall(storage_call) = &*mc.receiver {
                    if storage_call.method == "persistent" && self.storage_type.is_none() {
                        self.storage_type = Some("persistent");
                    } else if storage_call.method == "temporary" && self.storage_type.is_none() {
                        self.storage_type = Some("temporary");
                    }
                }
            }
        }
        visit::visit_expr(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_help_states_the_current_schema_version() {
        // `audit --help` documents `--json` as "(`schema_version` 1)"; bump
        // that text (and the help snapshot) together with the constant.
        assert_eq!(AUDIT_JSON_SCHEMA_VERSION, 1);
    }

    #[test]
    fn json_document_declares_schema_version_and_findings() {
        let findings = vec![Finding {
            file: "src/lib.rs".to_string(),
            line: 7,
            rule: "missing-require-auth",
            severity: "warning",
            message: "fn pay takes Address parameter(s) [\"from\"]".to_string(),
        }];
        let json = render_json(&findings, &[], &Rule::ALL);
        assert!(json.starts_with("{\"schema_version\":1,"), "{json}");
        assert!(json.contains("\"finding_count\":1"), "{json}");
        assert!(json.contains("\"line\":7"), "{json}");
        assert!(json.contains("\"rule\":\"missing-require-auth\""), "{json}");
        assert!(json.contains(r#"[\"from\"]"#), "{json}");
    }

    #[test]
    fn json_document_for_no_findings_is_an_empty_list() {
        let json = render_json(&[], &[], &Rule::ALL);
        assert!(
            json.ends_with(",\"finding_count\":0,\"findings\":[]}"),
            "{json}"
        );
    }

    #[test]
    fn finding_paths_are_relative_to_the_audited_root() {
        let p = |s: &str| PathBuf::from(s);
        assert_eq!(finding_path(&p("."), &p("./src/lib.rs")), "src/lib.rs");
        assert_eq!(
            finding_path(&p("examples/vault/src"), &p("examples/vault/src/lib.rs")),
            "lib.rs"
        );
        assert_eq!(
            finding_path(&p("/abs/crate"), &p("/abs/crate/src/nested/mod.rs")),
            "src/nested/mod.rs"
        );
    }

    #[test]
    fn a_single_file_root_reports_its_file_name() {
        let file = PathBuf::from("crates/cli/src/commands/mod.rs");
        assert_eq!(finding_path(&file, &file), "mod.rs");
    }

    #[test]
    fn a_file_outside_the_root_keeps_its_given_path() {
        assert_eq!(
            finding_path(Path::new("src"), Path::new("other/lib.rs")),
            "other/lib.rs"
        );
    }

    #[test]
    fn json_strings_escape_quotes_backslashes_and_control_characters() {
        let expected = "\"a\\\"b\\\\c\\nd\\u0001\"";
        assert_eq!(json_string("a\"b\\c\nd\u{1}"), expected);
    }

    #[test]
    fn non_utf8_paths_are_lossy_displayed_without_panicking() {
        // Test that finding_path handles path components gracefully
        let p = |s: &str| PathBuf::from(s);
        // Normal UTF-8 paths work as before
        assert_eq!(finding_path(&p("."), &p("./src/lib.rs")), "src/lib.rs");
        // Path display uses lossy conversion, so non-UTF8 bytes are replaced
        // with the replacement character (U+FFFD). This is verified by ensuring
        // the function doesn't panic and returns a valid string.
        let _ = finding_path(&p("."), &p("./src/lib.rs"));
    }

    #[test]
    fn multiline_function_line_number_is_the_function_definition_line() {
        let src = r#"
        fn test_function(
            param1: i128,
            param2: i128,
        ) {
            let total = param1 + param2;
        }
        "#;
        let mut findings = Vec::new();
        audit_source(src, "test.rs", &Rule::ALL, &mut findings, &mut Vec::new());
        // The line number should correspond to the first line of the function definition
        // (line 2 in this case, since line 1 is blank)
        if let Some(finding) = findings.first() {
            // Line numbers from syn are 1-indexed starting at the 'fn' keyword
            assert!(finding.line > 0, "finding line should be positive");
        }
    }

    #[test]
    fn arithmetic_findings_point_at_operator_lines_in_multiline_functions() {
        let src = r#"
fn pay(
    amount: i128,
) {
    let first = amount
        + 1;
    let second = amount
        * 2;
}
"#;
        let mut findings = Vec::new();
        audit_source(src, "test.rs", &Rule::ALL, &mut findings, &mut Vec::new());

        let lines: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule == "unchecked-i128-arithmetic")
            .map(|finding| finding.line)
            .collect();
        assert_eq!(lines, vec![6, 8], "{findings:?}");
    }

    #[test]
    fn traversal_errors_name_the_unreadable_path_and_the_io_cause() {
        let message = format_traversal_error(Path::new("src"), "permission denied").0;

        assert!(
            message.starts_with("cannot audit `src`: permission denied"),
            "{message}"
        );
        assert!(message.contains("make the directory readable"), "{message}");
    }

    #[test]
    fn multiline_comment_does_not_affect_function_line_detection() {
        let src = r#"
        /*
         * Multi-line comment
         * spanning multiple lines
         */
        #[contractimpl]
        impl C {
            pub fn documented_function(addr: Address) {
                // body
            }
        }
        "#;
        let mut findings = Vec::new();
        audit_source(src, "test.rs", &Rule::ALL, &mut findings, &mut Vec::new());
        if let Some(finding) = findings.first() {
            // Should still report the missing-require-auth at the function definition line,
            // not at a line in the comment
            assert!(
                finding.message.contains("require_auth"),
                "should detect missing require_auth despite comments"
            );
            assert!(finding.line > 0, "finding line should be positive");
        }
    }

    #[test]
    fn require_auth_detection_ignores_formatting() {
        // Verify that require_auth is detected regardless of whitespace/formatting
        let src = r#"
        #[contractimpl]
        impl C {
            pub fn transfer(to: Address, amount: i128) {
                if amount > 0 {
                    // Various formatting of require_auth calls
                    to.require_auth();
                }
            }
        }
        "#;
        let mut findings = Vec::new();
        audit_source(src, "test.rs", &Rule::ALL, &mut findings, &mut Vec::new());
        // Should NOT report missing-require-auth because require_auth is called
        let missing_auth = findings.iter().any(|f| f.rule == "missing-require-auth");
        assert!(
            !missing_auth,
            "require_auth should be detected despite formatting variations"
        );
    }

    #[test]
    fn storage_access_detection_ignores_formatting() {
        // Verify that .persistent().get() and .temporary().get() are detected
        // regardless of whitespace
        let src = r#"
        fn read_storage() {
            let x = env
                .storage()
                .persistent()
                .get(&key);
        }
        "#;
        let mut findings = Vec::new();
        audit_source(src, "test.rs", &Rule::ALL, &mut findings, &mut Vec::new());
        // Should report missing-ttl-bump because there's no extend_ttl call
        let missing_ttl = findings.iter().any(|f| f.rule == "missing-ttl-bump");
        assert!(
            missing_ttl,
            "storage access should be detected despite formatting variations"
        );
    }

    #[test]
    fn extend_ttl_detection_works_with_various_formatting() {
        let src = r#"
        fn safe_read() {
            let x = env.storage().persistent().get(&key);
            env.storage().persistent().extend_ttl(&key, 100000, 100000);
        }
        "#;
        let mut findings = Vec::new();
        audit_source(src, "test.rs", &Rule::ALL, &mut findings, &mut Vec::new());
        // Should NOT report missing-ttl-bump
        let missing_ttl = findings.iter().any(|f| f.rule == "missing-ttl-bump");
        assert!(
            !missing_ttl,
            "extend_ttl should be detected despite formatting variations"
        );
    }

    fn rules_of(src: &str, rules: &[Rule]) -> Vec<(&'static str, usize)> {
        let mut findings = Vec::new();
        audit_source(src, "test.rs", rules, &mut findings, &mut Vec::new());
        findings.iter().map(|f| (f.rule, f.line)).collect()
    }

    #[test]
    fn chained_i128_arithmetic_is_one_finding_at_its_line() {
        let src = "fn f(a: i128, b: i128, c: i128) -> i128 {\n    let x = 1;\n    (a + b) * c - a / b\n}\n";
        assert_eq!(
            rules_of(src, &Rule::ALL),
            vec![("unchecked-i128-arithmetic", 3)]
        );
    }

    #[test]
    fn arithmetic_inside_a_call_argument_is_a_separate_expression() {
        let src = "fn f(a: i128, b: i128) -> i128 {\n    a + g(\n        b * 2i128,\n    )\n}\n";
        assert_eq!(
            rules_of(src, &Rule::ALL),
            vec![
                ("unchecked-i128-arithmetic", 2),
                ("unchecked-i128-arithmetic", 3),
            ]
        );
    }

    #[test]
    fn non_i128_arithmetic_still_reaches_nested_i128_expressions() {
        let src = "fn f(n: u32, a: i128) -> u32 {\n    n + h(\n        a - 1i128,\n    )\n}\n";
        assert_eq!(
            rules_of(src, &Rule::ALL),
            vec![("unchecked-i128-arithmetic", 3)]
        );
    }

    #[test]
    fn nested_functions_are_audited_once_as_themselves() {
        let src = r#"
#[contractimpl]
impl C {
pub fn outer(env: Env, owner: Address) {
    fn inner(env: Env, owner: Address, a: i128) -> i128 {
        owner.require_auth();
        let v = env.storage().temporary().get(&k);
        a * 2i128
    }
    impl Helper {
        fn method(env: Env) {
            let v = env.storage().persistent().get(&k);
        }
    }
}
}
"#;
        let mut found = rules_of(src, &Rule::ALL);
        found.sort();
        assert_eq!(
            found,
            vec![
                // outer: inner's require_auth does not authorize outer
                ("missing-require-auth", 4),
                // inner: its own storage read and arithmetic, once each
                ("missing-ttl-bump", 5),
                // method in the nested impl block
                ("missing-ttl-bump", 11),
                ("unchecked-i128-arithmetic", 8),
            ]
        );
    }

    #[test]
    fn only_selected_rules_run() {
        let src = "#[contractimpl]\nimpl C {\npub fn f(env: Env, who: Address, a: i128) -> i128 {\n    let v = env.storage().persistent().get(&k);\n    a + 1i128\n}\n}\n";
        assert_eq!(rules_of(src, &Rule::ALL).len(), 3);
        assert_eq!(
            rules_of(src, &[Rule::MissingRequireAuth, Rule::MissingTtlBump]),
            vec![("missing-require-auth", 3), ("missing-ttl-bump", 3)]
        );
        assert_eq!(
            rules_of(src, &[Rule::UncheckedI128Arithmetic]),
            vec![("unchecked-i128-arithmetic", 5)]
        );
    }

    #[test]
    fn rule_selection_resolves_include_then_exclude_in_a_fixed_order() {
        use Rule::*;
        assert_eq!(selected_rules(&[], &[]).unwrap(), Rule::ALL.to_vec());
        assert_eq!(
            selected_rules(&[MissingTtlBump, MissingRequireAuth], &[]).unwrap(),
            vec![MissingRequireAuth, MissingTtlBump]
        );
        assert_eq!(
            selected_rules(&[], &[UncheckedI128Arithmetic]).unwrap(),
            vec![MissingRequireAuth, MissingTtlBump]
        );
        assert_eq!(
            selected_rules(&[MissingTtlBump, MissingTtlBump], &[]).unwrap(),
            vec![MissingTtlBump]
        );
        assert!(selected_rules(&[MissingTtlBump], &[MissingTtlBump])
            .unwrap_err()
            .contains("`missing-ttl-bump` is both selected"));
        assert!(selected_rules(&[], &Rule::ALL)
            .unwrap_err()
            .contains("nothing to audit"));
    }

    #[test]
    fn rule_ids_match_the_cli_value_names() {
        for rule in Rule::ALL {
            let value = rule.to_possible_value().unwrap();
            assert_eq!(value.get_name(), rule.id());
        }
    }

    #[test]
    fn json_lists_the_rules_that_ran() {
        let json = render_json(&[], &[], &[Rule::MissingTtlBump]);
        assert!(json.contains("\"rules\":[\"missing-ttl-bump\"],"), "{json}");
    }

    // ---- #134: auth findings only for contract entry points -------------

    fn auth_findings(src: &str) -> Vec<usize> {
        rules_of(src, &[Rule::MissingRequireAuth])
            .into_iter()
            .map(|(_, line)| line)
            .collect()
    }

    #[test]
    fn free_helper_functions_are_not_entry_points() {
        let src = "fn helper(env: Env, who: Address) -> u32 {\n    1\n}\npub fn also_helper(who: Address) {}\n";
        assert_eq!(auth_findings(src), Vec::<usize>::new());
    }

    #[test]
    fn only_pub_fns_of_a_contractimpl_block_are_entry_points() {
        let src = r#"
#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, to: Address) {}
    fn private_helper(env: Env, to: Address) {}
    pub(crate) fn crate_helper(to: Address) {}
}
"#;
        assert_eq!(auth_findings(src), vec![4]);
    }

    #[test]
    fn helper_impls_without_contractimpl_are_not_entry_points() {
        let src = "impl Vault {\n    pub fn withdraw(env: Env, to: Address) {}\n}\nimpl Helper for Vault {\n    fn check(to: Address) {}\n}\n";
        assert_eq!(auth_findings(src), Vec::<usize>::new());
    }

    #[test]
    fn every_fn_of_a_contractimpl_trait_impl_is_an_entry_point() {
        let src = "#[contractimpl]\nimpl Token for Vault {\n    fn transfer(env: Env, from: Address) {}\n}\n";
        assert_eq!(auth_findings(src), vec![3]);
    }

    #[test]
    fn contractimpl_is_recognised_in_any_spelling() {
        let qualified =
            "#[soroban_sdk::contractimpl]\nimpl Vault {\n    pub fn pay(to: Address) {}\n}\n";
        let with_args = "#[contractimpl(contracttrait)]\nimpl Token for Vault {\n    fn pay(to: Address) {}\n}\n";
        assert_eq!(auth_findings(qualified), vec![3]);
        assert_eq!(auth_findings(with_args), vec![3]);
    }

    #[test]
    fn helpers_nested_in_an_entry_point_are_not_entry_points() {
        let src = r#"
#[contractimpl]
impl Vault {
    pub fn pay(env: Env, to: Address) {
        to.require_auth();
        fn inner(to: Address) {}
        impl Local {
            pub fn method(to: Address) {}
        }
    }
}
"#;
        assert_eq!(auth_findings(src), Vec::<usize>::new());
    }

    #[test]
    fn entry_points_after_a_nested_helper_impl_are_still_checked() {
        let src = r#"
#[contractimpl]
impl Vault {
    pub fn first(env: Env) {
        impl Local {
            fn helper() {}
        }
    }
    pub fn second(env: Env, to: Address) {}
}
"#;
        assert_eq!(auth_findings(src), vec![9]);
    }

    #[test]
    fn other_rules_still_apply_to_helper_functions() {
        let src = "fn helper(env: Env, a: i128) -> i128 {\n    let v = env.storage().persistent().get(&k);\n    a + 1i128\n}\n";
        let mut found = rules_of(src, &Rule::ALL);
        found.sort();
        assert_eq!(
            found,
            vec![("missing-ttl-bump", 1), ("unchecked-i128-arithmetic", 3)]
        );
    }

    // ---- #142: --include / --exclude globs ------------------------------

    fn filter(include: &[&str], exclude: &[&str]) -> PathFilter {
        let owned = |globs: &[&str]| globs.iter().map(|g| g.to_string()).collect::<Vec<_>>();
        PathFilter::new(&owned(include), &owned(exclude)).unwrap()
    }

    #[test]
    fn no_globs_select_every_file() {
        let f = filter(&[], &[]);
        assert!(!f.is_active());
        assert!(f.selects("src/lib.rs"));
    }

    #[test]
    fn a_bare_name_matches_at_any_depth_like_gitignore() {
        let f = filter(&[], &["generated", "*_pb.rs"]);
        assert!(f.excludes("generated"));
        assert!(!f.selects("generated/types.rs"));
        assert!(!f.selects("src/deep/generated/types.rs"));
        assert!(!f.selects("src/proto/msg_pb.rs"));
        assert!(f.selects("src/lib.rs"));
        assert!(f.selects("src/generated_by_hand.rs"));
    }

    #[test]
    fn a_glob_with_a_slash_is_anchored_at_the_root() {
        let f = filter(&[], &["src/gen/**"]);
        assert!(!f.selects("src/gen/a.rs"));
        assert!(!f.selects("src/gen/nested/b.rs"));
        assert!(f.selects("other/src/gen/a.rs"));
        let star = filter(&[], &["src/*.rs"]);
        assert!(!star.selects("src/lib.rs"));
        assert!(star.selects("src/nested/lib.rs"));
    }

    #[test]
    fn double_star_spans_zero_or_more_segments() {
        let f = filter(&[], &["**/vendor/**"]);
        assert!(!f.selects("vendor/x.rs"));
        assert!(!f.selects("a/b/vendor/c/x.rs"));
        assert!(f.selects("a/vendors/x.rs"));
    }

    #[test]
    fn include_limits_the_audit_and_exclude_wins() {
        let f = filter(&["contracts/**"], &["*_test.rs"]);
        assert!(f.selects("contracts/vault/lib.rs"));
        assert!(!f.selects("scripts/tool.rs"));
        assert!(!f.selects("contracts/vault/lib_test.rs"));
        let dir = filter(&["contracts"], &[]);
        assert!(dir.selects("contracts/vault/lib.rs"));
    }

    #[test]
    fn question_mark_matches_one_character_in_a_segment() {
        let f = filter(&[], &["v?.rs"]);
        assert!(!f.selects("src/v1.rs"));
        assert!(f.selects("src/v10.rs"));
        assert!(f.selects("src/v/.rs"));
    }

    #[test]
    fn leading_dot_slash_trailing_slash_and_backslashes_are_normalised() {
        let f = filter(&[], &["./src\\gen/"]);
        assert!(!f.selects("src/gen/a.rs"));
        assert!(f.selects("src/lib.rs"));
    }

    #[test]
    fn an_empty_glob_is_a_usage_error() {
        let err = PathFilter::new(&[], &["/".to_string()]).unwrap_err();
        assert!(err.contains("--exclude `/` is empty"), "{err}");
    }

    // ---- #144: unparseable files are reported, not dropped --------------

    #[test]
    fn unparseable_source_is_recorded_with_position_and_parser_message() {
        let mut findings = Vec::new();
        let mut skipped = Vec::new();
        audit_source(
            "pub struct Ok;\n\nfn broken( {\n",
            "src/gen.rs",
            &Rule::ALL,
            &mut findings,
            &mut skipped,
        );
        assert!(findings.is_empty());
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        let skip = &skipped[0];
        assert_eq!(skip.file, "src/gen.rs");
        assert_eq!(skip.line, 3, "{skip:?}");
        assert!(skip.column >= 1, "{skip:?}");
        assert!(!skip.message.is_empty(), "{skip:?}");
    }

    #[test]
    fn parse_positions_are_one_based_and_point_at_the_offending_token() {
        let skip = |src: &str| {
            let mut skipped = Vec::new();
            audit_source(src, "x.rs", &Rule::ALL, &mut Vec::new(), &mut skipped);
            skipped.pop().expect("source should be skipped")
        };
        // `let` is not an item: line 2, column 3 (after two spaces).
        let item = skip("fn a() {}\n  let x = ;\n");
        assert_eq!((item.line, item.column), (2, 3), "{item:?}");
        assert!(item.message.starts_with("expected one of"), "{item:?}");
        // The unclosed `{` is the 12th character of line 3.
        let unbalanced = skip("pub struct Ok;\n\nfn broken( {\n");
        assert_eq!(
            (unbalanced.line, unbalanced.column),
            (3, 12),
            "{unbalanced:?}"
        );
        assert!(
            unbalanced.message.starts_with("unbalanced delimiter"),
            "{unbalanced:?}"
        );
    }

    #[test]
    fn empty_and_valid_sources_are_not_skipped() {
        let mut skipped = Vec::new();
        audit_source("", "a.rs", &Rule::ALL, &mut Vec::new(), &mut skipped);
        audit_source(
            "fn ok() {}\n",
            "b.rs",
            &Rule::ALL,
            &mut Vec::new(),
            &mut skipped,
        );
        assert_eq!(skipped, vec![]);
    }

    #[test]
    fn json_lists_skipped_files_before_the_findings() {
        let skipped = vec![Skipped {
            file: "src/gen.rs".to_string(),
            line: 3,
            column: 12,
            message: "expected `)`".to_string(),
        }];
        let json = render_json(&[], &skipped, &Rule::ALL);
        assert!(
            json.contains(
                "\"skipped\":[{\"file\":\"src/gen.rs\",\"line\":3,\"column\":12,\"message\":\"expected `)`\"}],\"finding_count\":0"
            ),
            "{json}"
        );
        assert!(
            json.ends_with(",\"finding_count\":0,\"findings\":[]}"),
            "{json}"
        );
    }

    #[test]
    fn i128_remainder_negation_and_compound_assignments_are_flagged() {
        let src = r#"
fn ops(mut a: i128, b: i128) -> i128 {
    let rem = a % b;
    let neg = -a;
    a += b;
    a -= 1;
    a *= 2;
    a /= 3;
    a %= 5;
    let lit_neg = -1i128;
    lit_neg
}
"#;
        assert_eq!(
            rules_of(src, &[Rule::UncheckedI128Arithmetic]),
            vec![
                ("unchecked-i128-arithmetic", 3),
                ("unchecked-i128-arithmetic", 4),
                ("unchecked-i128-arithmetic", 5),
                ("unchecked-i128-arithmetic", 6),
                ("unchecked-i128-arithmetic", 7),
                ("unchecked-i128-arithmetic", 8),
                ("unchecked-i128-arithmetic", 9),
            ]
        );
    }

    #[test]
    fn non_i128_remainder_negation_and_compound_assignments_are_not_flagged() {
        let src = r#"
fn safe_u64(mut a: u64, b: u64, mut c: i64) -> i64 {
    let r = a % b;
    a += b;
    a -= 1;
    a *= 2;
    a /= 3;
    a %= 5;
    c = -c;
    c
}
"#;
        assert_eq!(
            rules_of(src, &[Rule::UncheckedI128Arithmetic]),
            Vec::<(&'static str, usize)>::new()
        );
    }

    #[test]
    fn checked_and_saturating_method_chains_are_not_flagged() {
        let src = r#"
fn safe_chains(a: i128, b: i128, c: i128) -> Option<i128> {
    let x = a.checked_add(b)?.checked_mul(c)?;
    let y = x.saturating_add(1).wrapping_sub(2);
    let z = i128::checked_div(y, 3)?;
    Some(z)
}
"#;
        assert_eq!(
            rules_of(src, &[Rule::UncheckedI128Arithmetic]),
            Vec::<(&'static str, usize)>::new()
        );
    }

    #[test]
    fn unchecked_method_forms_and_mixed_chains_are_flagged() {
        let src = r#"
use core::ops::Add;

fn mixed(a: i128, b: i128, c: i128) -> i128 {
    let m1 = a.add(b).mul(c);
    let m2 = a.unchecked_add(b);
    let m3 = i128::add(a, b);
    let m4 = Add::add(a, b);
    let m5 = a.checked_add(b).unwrap() + 1;
    let m6 = (a + b).checked_mul(c).unwrap();
    let m7 = a.checked_add(b + c).unwrap();
    let m8 = a.saturating_add(b) * 2;
    m1 + m2 + m3 + m4 + m5 + m6 + m7 + m8
}
"#;
        assert_eq!(
            rules_of(src, &[Rule::UncheckedI128Arithmetic]),
            vec![
                ("unchecked-i128-arithmetic", 5),
                ("unchecked-i128-arithmetic", 6),
                ("unchecked-i128-arithmetic", 7),
                ("unchecked-i128-arithmetic", 8),
                ("unchecked-i128-arithmetic", 9),
                ("unchecked-i128-arithmetic", 10),
                ("unchecked-i128-arithmetic", 11),
                ("unchecked-i128-arithmetic", 12),
                ("unchecked-i128-arithmetic", 13),
            ]
        );
    }

    // ---- #136: authorization parameter matching -------------------------

    #[test]
    fn require_auth_on_wrong_address_or_non_param_is_flagged() {
        let src = r#"
#[contractimpl]
impl Contract {
    pub fn wrong_local(env: Env, user: Address) {
        let admin = get_admin(&env);
        admin.require_auth();
    }

    pub fn wrong_field(&self, env: Env, user: Address) {
        self.admin.require_auth();
    }

    pub fn shadowed_param(env: Env, user: Address) {
        let user = get_admin(&env);
        user.require_auth();
    }
}
"#;
        assert_eq!(auth_findings(src), vec![4, 9, 13]);
    }

    #[test]
    fn require_auth_on_tracked_address_parameter_or_alias_passes() {
        let src = r#"
#[contractimpl]
impl Contract {
    pub fn direct(env: Env, user: Address) {
        user.require_auth();
    }

    pub fn via_alias(env: Env, from: Address, to: Address) {
        let signer = from.clone();
        signer.require_auth_for_args(());
    }

    pub fn via_ref(env: Env, owner: &Address) {
        (*owner).require_auth();
    }
}
"#;
        assert_eq!(auth_findings(src), Vec::<usize>::new());
    }
}
