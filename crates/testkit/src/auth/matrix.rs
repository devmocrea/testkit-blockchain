use std::fmt;

use soroban_sdk::Address;

use crate::core::{TestEnv, TestkitError};

type InvokeFn<'a> = Box<dyn Fn(&Address) -> Result<(), soroban_sdk::Error> + 'a>;

/// Errors raised while building or evaluating an [`AuthMatrix`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatrixError {
    /// Two or more entries share the same name.
    DuplicateName(String),
}

impl fmt::Display for MatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatrixError::DuplicateName(name) => {
                write!(f, "duplicate auth matrix name: {name:?}")
            }
        }
    }
}

impl std::error::Error for MatrixError {}

/// A single cell in the authorization matrix evaluation grid, representing
/// an evaluation of a specific entry point with a candidate caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixCell {
    /// Name of the entry point being checked.
    pub entry_point: String,
    /// Candidate caller address tested against the entry point.
    pub caller: Address,
    /// Whether the caller was expected to succeed (`true`) or be rejected (`false`).
    pub expected: bool,
    /// Whether the call actually succeeded (`true`) or was rejected (`false`).
    pub actual: bool,
}

impl MatrixCell {
    /// Returns `true` if the actual outcome matched the expected outcome.
    pub fn is_match(&self) -> bool {
        self.expected == self.actual
    }

    /// Returns `true` if this cell is a violation (actual outcome differed from expected).
    pub fn is_violation(&self) -> bool {
        self.expected != self.actual
    }
}

/// A structured report produced by [`AuthMatrix::check`], recording per-cell
/// outcomes and the formatted evaluation grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixReport {
    /// Detailed per-cell outcomes for all evaluated (entry point, caller) pairs.
    pub cells: Vec<MatrixCell>,
    /// Formatted grid string showing expected vs actual outcomes.
    pub grid: String,
}

impl MatrixReport {
    /// Returns `true` if all cells matched their expected outcome.
    pub fn is_success(&self) -> bool {
        self.cells.iter().all(|c| c.is_match())
    }

    /// Returns `true` if all cells matched their expected outcome (alias for [`is_success`](Self::is_success)).
    pub fn is_enforced(&self) -> bool {
        self.is_success()
    }

    /// Returns a slice of all evaluated cells.
    pub fn cells(&self) -> &[MatrixCell] {
        &self.cells
    }

    /// Returns all cells where the actual outcome differed from expected.
    pub fn violations(&self) -> Vec<&MatrixCell> {
        self.cells.iter().filter(|c| c.is_violation()).collect()
    }

    /// Returns the formatted grid string.
    pub fn grid(&self) -> &str {
        &self.grid
    }
}

struct EntryPointSpec<'a> {
    name: String,
    allowed: Vec<Address>,
    invoke: InvokeFn<'a>,
}

/// A declarative table of who may call what, so that a contract's full
/// caller/entry-point grid is checked by default instead of the four cases
/// someone thought to write by hand.
///
/// Register each privileged entry point with [`AuthMatrix::entry_point`],
/// optionally register candidate callers with [`AuthMatrix::candidate`] or
/// [`AuthMatrix::candidates`], and then call [`AuthMatrix::assert_enforced`]
/// (or [`AuthMatrix::check`]) to verify that every allowed address succeeds
/// and every other address known to the matrix is rejected, for every entry point.
pub struct AuthMatrix<'a> {
    // Ties the matrix's lifetime to its TestEnv; entry point closures
    // capture their own references into it independently.
    #[allow(dead_code)]
    env: &'a TestEnv,
    entry_points: Vec<EntryPointSpec<'a>>,
    candidates: Vec<Address>,
}

impl<'a> AuthMatrix<'a> {
    /// Start an empty matrix against `env`.
    pub fn new(env: &'a TestEnv) -> Self {
        Self {
            env,
            entry_points: Vec::new(),
            candidates: Vec::new(),
        }
    }

    /// Register a privileged entry point: its name (for failure messages),
    /// the addresses permitted to call it, and a closure that attempts the
    /// call as a given caller, returning `Ok(())` if it succeeded and
    /// `Err` if the contract rejected it.
    ///
    /// An entry point with an empty allowed slice (`&[]`) is checked
    /// intentionally as having no authorized callers; all known callers
    /// will be expected to be rejected.
    ///
    /// `invoke` is typically built from a generated client's `try_*`
    /// method with the candidate address mocked as the caller — see
    /// [`AuthMatrix::assert_enforced`]'s example.
    pub fn entry_point(
        mut self,
        name: &str,
        allowed: &[Address],
        invoke: impl Fn(&Address) -> Result<(), soroban_sdk::Error> + 'a,
    ) -> Self {
        self.entry_points.push(EntryPointSpec {
            name: name.to_string(),
            allowed: allowed.to_vec(),
            invoke: Box::new(invoke),
        });
        self
    }

    /// Register an unauthorized or explicit candidate caller to test against
    /// all entry points, even if that address is not listed as `allowed` on
    /// any entry point.
    pub fn candidate(mut self, candidate: &Address) -> Self {
        self.candidates.push(candidate.clone());
        self
    }

    /// Register multiple candidate callers to test against all entry points.
    pub fn candidates(mut self, candidates: &[Address]) -> Self {
        self.candidates.extend_from_slice(candidates);
        self
    }

    /// Evaluate the authorization matrix across all registered entry points
    /// and candidate callers, returning a structured [`MatrixReport`].
    ///
    /// Unlike [`assert_enforced`](Self::assert_enforced), `check` does not panic
    /// when authorization invariants are violated, allowing callers to inspect
    /// per-cell expected and actual outcomes programmatically.
    ///
    /// If an entry point has an empty allowed caller list, all known callers are
    /// expected to be rejected. If zero callers are known across the entire matrix
    /// (every entry point has empty allowed callers and no candidates are registered),
    /// zero cells are evaluated and the report trivially succeeds.
    ///
    /// # Panics
    ///
    /// Panics if an invoke closure panics during execution, identifying the
    /// entry point and candidate caller while preserving the original panic payload.
    pub fn check(&self) -> MatrixReport {
        // Entry points are visited by name and callers by address, not in
        // registration order, so the grid and the failure message are the
        // same however (and however many times) the matrix was built. The
        // sort is stable, so entry points that share a name keep their
        // registration order relative to each other.
        let mut entry_points: Vec<&EntryPointSpec<'a>> = self.entry_points.iter().collect();
        entry_points.sort_by(|a, b| a.name.cmp(&b.name));

        let mut known: Vec<Address> = Vec::new();
        for ep in &entry_points {
            for addr in &ep.allowed {
                if !known.contains(addr) {
                    known.push(addr.clone());
                }
            }
        }
        for addr in &self.candidates {
            if !known.contains(addr) {
                known.push(addr.clone());
            }
        }
        known.sort_by_cached_key(|addr| format!("{addr:?}"));

        let mut cells = Vec::with_capacity(entry_points.len() * known.len());
        let mut grid = String::new();

        for ep in &entry_points {
            grid.push_str(&format!("  [{}]\n", ep.name));
            for addr in &known {
                let expected = ep.allowed.contains(addr);
                let actual = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    (ep.invoke)(addr)
                })) {
                    Ok(result) => result.is_ok(),
                    Err(payload) => {
                        let msg = crate::internal::panic_message(payload.as_ref());
                        panic!(
                            "{}",
                            TestkitError::AssertionFailed(format!(
                                "auth matrix invoke panicked for entry point {:?} and candidate caller {addr:?}: {msg}",
                                ep.name
                            ))
                        );
                    }
                };

                grid.push_str(&format!(
                    "    {addr:?}: expected={} actual={}{}\n",
                    if expected { "pass" } else { "reject" },
                    if actual { "pass" } else { "reject" },
                    if expected == actual {
                        ""
                    } else {
                        "  <-- MISMATCH"
                    },
                ));

                cells.push(MatrixCell {
                    entry_point: ep.name.clone(),
                    caller: addr.clone(),
                    expected,
                    actual,
                });
            }
        }

        MatrixReport { cells, grid }
    }

    /// For every registered entry point, assert every allowed address
    /// succeeds and every other address known to the matrix (i.e. named as
    /// `allowed` on *some* entry point, or registered via [`candidate`](Self::candidate)) fails.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] naming every
    /// violating (entry point, caller) cell, followed by the full grid
    /// (every cell's expected vs. actual outcome) so a passing cell isn't
    /// mistaken for a gap in coverage.
    ///
    /// Also panics if an invoke closure panics during execution, identifying
    /// the entry point and candidate caller while preserving the panic payload.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::auth::AuthMatrix;
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let owner = env.address();
    ///
    /// // A single-entry-point matrix where the only allowed caller is
    /// // itself: trivially enforced.
    /// AuthMatrix::new(&env)
    ///     .entry_point("noop", &[owner.clone()], move |caller| {
    ///         if *caller == owner {
    ///             Ok(())
    ///         } else {
    ///             Err(soroban_sdk::Error::from_contract_error(1))
    ///         }
    ///     })
    ///     .assert_enforced();
    /// ```
    pub fn assert_enforced(&self) {
        let report = self.check();
        let violations = report.violations();

        if !violations.is_empty() {
            let violation_messages: Vec<String> = violations
                .iter()
                .map(|c| {
                    format!(
                        "entry point {:?}: caller {:?} expected to {} but {}",
                        c.entry_point,
                        c.caller,
                        if c.expected { "succeed" } else { "be rejected" },
                        if c.actual { "succeeded" } else { "was rejected" },
                    )
                })
                .collect();

            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "auth matrix violated ({} of {} cells):\n{}\nfull grid:\n{}",
                    violations.len(),
                    report.cells.len(),
                    violation_messages.join("\n"),
                    report.grid,
                ))
            );
        }
    }
}

impl TestEnv {
    /// Assert that `f` fails when it runs without the authorization it
    /// requires — the single-call counterpart to [`AuthMatrix`], for a
    /// caller that just needs "this must reject an unauthorized attempt"
    /// without a full grid.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] if `f` completes
    /// (returns) instead of failing.
    ///
    /// # Example
    ///
    /// ```should_panic
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// // A closure that succeeds unconditionally can never satisfy this.
    /// env.assert_requires_auth(|| {});
    /// ```
    pub fn assert_requires_auth(&self, f: impl FnOnce()) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        if result.is_ok() {
            panic!(
                "{}",
                TestkitError::AssertionFailed(
                    "expected the call to fail without authorization, but it succeeded".into()
                )
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;
    use vault::{VaultClient, VaultError};

    fn flatten<T>(
        result: Result<
            Result<T, soroban_sdk::ConversionError>,
            Result<VaultError, soroban_sdk::InvokeError>,
        >,
    ) -> Result<(), soroban_sdk::Error> {
        match result {
            Ok(Ok(_)) => Ok(()),
            _ => Err(soroban_sdk::Error::from_contract_error(0)),
        }
    }

    #[test]
    fn assert_enforced_catches_a_real_missing_auth_bug() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // `deposit` is legitimately open to anyone, which is what puts
        // `attacker` into the matrix's "known addresses" set. `withdraw`
        // (the buggy entry point) never calls owner.require_auth(), so
        // when we check that only `owner` may withdraw, `attacker` — a
        // known address the matrix now cross-checks against every entry
        // point — incorrectly succeeds too. That's exactly the bug.
        let matrix = AuthMatrix::new(&env)
            .entry_point(
                "deposit",
                &[owner.clone(), attacker.clone()],
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "deposit",
                                args: (1_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_deposit(&1);
                    flatten(result)
                },
            )
            .entry_point(
                "withdraw",
                std::slice::from_ref(&owner),
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "withdraw",
                                args: (10_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_withdraw(&10);
                    flatten(result)
                },
            );

        let message = crate::testing::assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
            matrix.assert_enforced();
        });
        assert!(
            message.contains("withdraw"),
            "failure message should name the entry point: {message}"
        );
        assert!(
            message.contains(&format!("{attacker:?}")),
            "failure message should name the offending caller: {message}"
        );
    }

    #[test]
    fn assert_enforced_passes_once_the_bug_is_fixed() {
        let env = TestEnv::new();
        let owner = env.address();
        let other = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // Same shape as the buggy-case test (two entry points, so `other`
        // is a known address cross-checked against withdraw_checked), but
        // against the fixed entry point: `other` is correctly rejected.
        AuthMatrix::new(&env)
            .entry_point(
                "deposit",
                &[owner.clone(), other.clone()],
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "deposit",
                                args: (1_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_deposit(&1);
                    flatten(result)
                },
            )
            .entry_point(
                "withdraw_checked",
                std::slice::from_ref(&owner),
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "withdraw_checked",
                                args: (10_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_withdraw_checked(&10);
                    flatten(result)
                },
            )
            .assert_enforced();
    }

    #[test]
    fn assert_requires_auth_passes_when_call_panics() {
        let env = TestEnv::new();
        env.assert_requires_auth(|| panic!("simulated auth failure"));
    }

    #[test]
    #[should_panic(expected = "expected the call to fail without authorization")]
    fn assert_requires_auth_panics_when_call_succeeds() {
        let env = TestEnv::new();
        env.assert_requires_auth(|| {});
    }

    #[test]
    fn failure_grid_is_independent_of_registration_order_and_duplicate_allowed_addresses() {
        let env = TestEnv::new();
        let a = env.address();
        let b = env.address();

        // Both entry points wrongly accept everyone, so every cell where the
        // caller is not allowed is a violation.
        let build = |reverse: bool, repeat_allowed: bool| {
            let allowed_a: Vec<Address> = if repeat_allowed {
                vec![a.clone(), a.clone()]
            } else {
                vec![a.clone()]
            };
            let allowed_b = vec![b.clone()];
            let matrix = AuthMatrix::new(&env);
            if reverse {
                matrix
                    .entry_point("beta", &allowed_b, |_c: &Address| Ok(()))
                    .entry_point("alpha", &allowed_a, |_c: &Address| Ok(()))
            } else {
                matrix
                    .entry_point("alpha", &allowed_a, |_c: &Address| Ok(()))
                    .entry_point("beta", &allowed_b, |_c: &Address| Ok(()))
            }
        };

        let message = |reverse, repeat| {
            crate::testing::assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
                build(reverse, repeat).assert_enforced();
            })
        };

        let baseline = message(false, false);
        assert_eq!(baseline, message(true, false), "registration order changed the grid");
        assert_eq!(baseline, message(false, true), "a repeated allowed address changed the grid");
        assert_eq!(baseline, message(true, true));
        assert!(
            baseline.find("[alpha]").unwrap() < baseline.find("[beta]").unwrap(),
            "entry points should appear in name order: {baseline}"
        );
    }

    #[test]
    fn check_returns_structured_report_with_per_cell_outcomes() {
        let env = TestEnv::new();
        let alice = env.address();
        let bob = env.address();

        let matrix = AuthMatrix::new(&env)
            .entry_point("only_alice", &[alice.clone()], {
                let alice_clone = alice.clone();
                move |caller: &Address| {
                    if *caller == alice_clone {
                        Ok(())
                    } else {
                        Err(soroban_sdk::Error::from_contract_error(1))
                    }
                }
            })
            .candidate(&bob);

        let report = matrix.check();
        assert!(report.is_success());
        assert!(report.is_enforced());
        assert_eq!(report.violations().len(), 0);
        assert_eq!(report.cells().len(), 2);

        let alice_cell = report.cells().iter().find(|c| c.caller == alice).unwrap();
        assert_eq!(alice_cell.entry_point, "only_alice");
        assert!(alice_cell.expected);
        assert!(alice_cell.actual);
        assert!(alice_cell.is_match());
        assert!(!alice_cell.is_violation());

        let bob_cell = report.cells().iter().find(|c| c.caller == bob).unwrap();
        assert_eq!(bob_cell.entry_point, "only_alice");
        assert!(!bob_cell.expected);
        assert!(!bob_cell.actual);
        assert!(bob_cell.is_match());
        assert!(!bob_cell.is_violation());
    }

    #[test]
    fn check_records_violations_without_panicking() {
        let env = TestEnv::new();
        let alice = env.address();
        let bob = env.address();

        let matrix = AuthMatrix::new(&env)
            .entry_point("only_alice", &[alice.clone()], |_| Ok(()))
            .candidate(&bob);

        let report = matrix.check();
        assert!(!report.is_success());
        assert!(!report.is_enforced());
        assert_eq!(report.violations().len(), 1);
        let violation = report.violations()[0];
        assert_eq!(violation.caller, bob);
        assert!(!violation.expected);
        assert!(violation.actual);
        assert!(violation.is_violation());
        assert!(report.grid().contains("MISMATCH"));
    }

    #[test]
    fn invoke_panic_identifies_entry_point_and_candidate_caller_and_payload() {
        let env = TestEnv::new();
        let attacker = env.address();

        let matrix = AuthMatrix::new(&env).entry_point("failing_ep", &[attacker.clone()], |_| {
            panic!("custom panic payload from inside contract call");
        });

        let message = crate::testing::assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
            matrix.assert_enforced();
        });
        assert!(
            message.contains("failing_ep"),
            "should identify entry point in panic message: {message}"
        );
        assert!(
            message.contains(&format!("{attacker:?}")),
            "should identify candidate caller in panic message: {message}"
        );
        assert!(
            message.contains("custom panic payload from inside contract call"),
            "should preserve original panic payload: {message}"
        );
    }

    #[test]
    fn candidate_registration_checks_candidates_across_all_entry_points() {
        let env = TestEnv::new();
        let admin = env.address();
        let intruder = env.address();

        let matrix = AuthMatrix::new(&env)
            .entry_point("admin_fn", &[admin.clone()], {
                let admin_clone = admin.clone();
                move |caller: &Address| {
                    if *caller == admin_clone {
                        Ok(())
                    } else {
                        Err(soroban_sdk::Error::from_contract_error(1))
                    }
                }
            })
            .candidate(&intruder);

        matrix.assert_enforced();

        let buggy_matrix = AuthMatrix::new(&env)
            .entry_point("admin_fn", &[admin.clone()], |_| Ok(()))
            .candidates(&[intruder.clone()]);

        let message = crate::testing::assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
            buggy_matrix.assert_enforced();
        });
        assert!(message.contains(&format!("{intruder:?}")));
    }

    #[test]
    fn empty_allowed_caller_list_rejects_known_callers_and_handles_zero_known() {
        let env = TestEnv::new();
        let user = env.address();

        // 1. Entry point with empty allowed list: any known caller must be rejected
        let matrix = AuthMatrix::new(&env)
            .entry_point("locked_endpoint", &[], |_caller| {
                Err(soroban_sdk::Error::from_contract_error(403))
            })
            .candidate(&user);

        matrix.assert_enforced();
        let report = matrix.check();
        assert_eq!(report.cells().len(), 1);
        assert!(!report.cells()[0].expected);
        assert!(!report.cells()[0].actual);

        // 2. If it incorrectly accepts the caller, assertion fails
        let failing_matrix = AuthMatrix::new(&env)
            .entry_point("locked_endpoint", &[], |_caller| Ok(()))
            .candidate(&user);

        crate::testing::assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
            failing_matrix.assert_enforced();
        });

        // 3. Zero known callers overall (empty allowed list and no candidates registered)
        let zero_matrix = AuthMatrix::new(&env).entry_point("no_callers", &[], |_| Ok(()));
        let zero_report = zero_matrix.check();
        assert_eq!(zero_report.cells().len(), 0);
        assert!(zero_report.is_success());
        zero_matrix.assert_enforced();
    }
}
