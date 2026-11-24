use soroban_sdk::testutils::storage::{Instance as _, Persistent as _, Temporary as _};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{Address, Env, IntoVal, Val};

use crate::core::{TestEnv, TestkitError};

/// Which of Soroban's three storage kinds an entry lives in. TTL semantics
/// differ per kind — see [`TestEnv::ttl_of`] and [`TestEnv::expire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    /// Cheapest, expires soonest, and once gone is gone — used for data
    /// that's fine to lose (e.g. rate-limit counters, session state).
    Temporary,
    /// Long-lived, rent-paying storage. Expired entries can be restored by
    /// re-writing them; reading an expired entry panics.
    Persistent,
    /// The contract's own instance data (its "self" storage) plus its
    /// code. There is exactly one instance entry per contract, so
    /// [`TestEnv::ttl_of`] ignores the `key` parameter for this kind.
    Instance,
}

impl TestEnv {
    /// The current TTL of a storage entry, in ledgers.
    ///
    /// Ignores `key` for [`StorageKind::Instance`], which has one TTL per
    /// contract rather than one per key.
    ///
    /// # Expiry boundary
    ///
    /// The value counts the ledgers left until expiry *excluding* the current
    /// ledger, and the host treats an entry as live while
    /// `live_until_ledger >= current_sequence`. An entry therefore stays
    /// readable through the ledger where its TTL has fallen to `0` — its
    /// **last live ledger** — and only expires once the ledger advances past
    /// it. What "expired" then means differs per kind:
    ///
    /// * [`StorageKind::Temporary`] — the entry is dropped: reads see nothing
    ///   and this method panics.
    /// * [`StorageKind::Persistent`] and [`StorageKind::Instance`] — the
    ///   entry is auto-restored on access (instance entries carry persistent
    ///   durability), so reads still return the value and this method reports
    ///   a fresh, positive TTL instead of panicking.
    ///
    /// # Panics
    ///
    /// Panics if the entry does not exist, or — for
    /// [`StorageKind::Persistent`] and [`StorageKind::Temporary`] — has
    /// already expired. This matches `soroban_sdk::testutils`' own
    /// `get_ttl` methods, which this is built on.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// StoreClient::new(env.env(), &id).set(&symbol_short!("k"), &1);
    ///
    /// let ttl = env.ttl_of(&id, StorageKind::Persistent, symbol_short!("k"));
    /// assert!(ttl > 0);
    /// # }
    /// ```
    pub fn ttl_of<K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        key: K,
    ) -> u32 {
        let key_val = key.into_val(self.env());
        self.ttl_of_val(contract, kind, &key_val)
    }

    /// A compact snapshot of the current TTLs of several *named* keys.
    ///
    /// [`TestEnv::ttl_of`] reads one entry at a time; this reads a whole set
    /// of keys of a single `kind` in one call and returns each TTL tagged
    /// with the name it was given, in the order the keys were supplied. That
    /// makes it easy to assert on several entries at once — for example, that
    /// bumping one key left its neighbours untouched — or to log a footprint
    /// at a point in time.
    ///
    /// # Scope
    ///
    /// Bounded to exactly the keys supplied and the single `kind` supplied:
    /// nothing else in storage is read, and the order of the returned
    /// snapshot mirrors the order of `named_keys`. Every key must share one
    /// type `K`; the names are what distinguish them. For
    /// [`StorageKind::Instance`] there is one entry per contract, so the key
    /// is ignored (as in [`TestEnv::ttl_of`]) and every name reports the same
    /// instance TTL.
    ///
    /// # Panics
    ///
    /// Panics if any named entry does not exist, or — for
    /// [`StorageKind::Persistent`] and [`StorageKind::Temporary`] — has
    /// already expired, exactly as [`TestEnv::ttl_of`] does. Keys are read in
    /// order, so a panic leaves the entries before the offending key already
    /// read (their values are simply discarded).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// let client = StoreClient::new(env.env(), &id);
    /// client.set(&symbol_short!("a"), &1);
    /// client.set(&symbol_short!("b"), &2);
    ///
    /// let snapshot = env.ttl_snapshot(
    ///     &id,
    ///     StorageKind::Persistent,
    ///     [("a", symbol_short!("a")), ("b", symbol_short!("b"))],
    /// );
    /// assert_eq!(snapshot.len(), 2);
    /// assert_eq!(snapshot[0].0, "a");
    /// assert_eq!(snapshot[1].0, "b");
    /// # }
    /// ```
    pub fn ttl_snapshot<'a, K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        named_keys: impl IntoIterator<Item = (&'a str, K)>,
    ) -> Vec<(&'a str, u32)> {
        named_keys
            .into_iter()
            .map(|(name, key)| (name, self.ttl_of(contract, kind, key)))
            .collect()
    }

    /// Advance the ledger far enough that every entry — regardless of
    /// `kind` — expires.
    ///
    /// `kind` is accepted for symmetry with the rest of this module and to
    /// document intent at the call site, but does not change the amount
    /// advanced: from outside a contract, there is no way to know how much
    /// TTL headroom a specific entry has without calling
    /// [`TestEnv::ttl_of`] on it individually, and an entry of any kind
    /// may have been extended up to the network's `max_entry_ttl`. So this
    /// reads `max_entry_ttl` from the environment's current ledger info at
    /// runtime (never hardcoded — see [`crate::ledger::LEDGER_CLOSE_TIME_SECS`] for the
    /// same reasoning applied to ledger close time) and advances one
    /// ledger past it, which guarantees expiry for every kind at once.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    ///
    /// let env = TestEnv::new();
    /// env.expire(StorageKind::Persistent);
    /// ```
    pub fn expire(&self, kind: StorageKind) {
        let _ = kind;
        let max_entry_ttl = self.env().ledger().get().max_entry_ttl;
        self.advance_ledgers(max_entry_ttl.saturating_add(1));
    }

    /// Assert that running `f` extends the TTL of the entry at `contract`/
    /// `kind`/`key` beyond what it was before `f` ran.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] showing the before
    /// and after TTLs if `f` did not increase it.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    ///     pub fn touch(env: Env, key: Symbol) {
    ///         env.storage().persistent().extend_ttl(&key, 5_000, 10_000);
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// let client = StoreClient::new(env.env(), &id);
    /// client.set(&symbol_short!("k"), &1);
    ///
    /// env.assert_bumps_ttl(&id, StorageKind::Persistent, symbol_short!("k"), || {
    ///     client.touch(&symbol_short!("k"));
    /// });
    /// # }
    /// ```
    pub fn assert_bumps_ttl<K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        key: K,
        f: impl FnOnce(),
    ) {
        let key_val = key.into_val(self.env());
        let before = self.ttl_of_val(contract, kind, &key_val);
        f();
        let after = self.ttl_of_val(contract, kind, &key_val);
        if after <= before {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the call to extend the {kind:?} TTL beyond {before}, but it was {after} afterward"
                ))
            );
        }
    }

    /// Assert that `f` completes without panicking after every entry of
    /// `kind` has expired (via [`TestEnv::expire`]) — i.e. that the
    /// contract handles an expired/missing entry gracefully instead of
    /// trapping on it.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] naming the underlying
    /// panic if `f` panics.
    ///
    /// # Preserved detail
    ///
    /// The message carries the closure's panic payload, so the failure says
    /// *why* the contract did not survive rather than only that it panicked.
    /// A string payload is shown verbatim; a payload carrying an SDK error is
    /// shown through its `Debug` form, which preserves the contract error
    /// code (for example `Error(Contract, #1)`). A payload of any other shape
    /// is reported as `<non-string panic payload>`.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    ///
    /// let env = TestEnv::new();
    /// env.assert_survives_expiry(StorageKind::Temporary, || {
    ///     // A closure that never touches the expired entry trivially survives.
    /// });
    /// ```
    pub fn assert_survives_expiry(&self, kind: StorageKind, f: impl FnOnce()) {
        self.expire(kind);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        if let Err(payload) = result {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the contract to survive {kind:?} storage expiry gracefully, \
                     but it panicked: {}",
                    crate::internal::panic_message(payload.as_ref())
                ))
            );
        }
    }

    /// The [`Result`]-aware companion to [`TestEnv::assert_survives_expiry`]:
    /// assert that `f` completes without panicking *and* returns `Ok`, after
    /// every entry of `kind` has expired (via [`TestEnv::expire`]).
    ///
    /// Contracts commonly signal a handled missing/expired entry by returning
    /// an error rather than trapping, and [`TestEnv::assert_survives_expiry`]
    /// would score that `Err` as a pass because the closure itself did not
    /// panic. Here a returned `Err` fails the assertion.
    ///
    /// # Scope
    ///
    /// Only the closure's own outcome is inspected — a panic *or* an `Err`.
    /// The error is rendered through its [`Debug`] form. On success the `Ok`
    /// value is handed back to the caller, so this doubles as "run `f` and
    /// give me its `Ok`". Only the outer level of a nested result is
    /// inspected: a `Result<Result<_, _>, _>` (for example what a generated
    /// `try_*` client method returns for a `Result`-returning entry point)
    /// flattens in the closure if you want the inner error to fail too.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] naming the underlying
    /// panic if `f` panics, or showing the returned error if `f` returns
    /// `Err`.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().temporary().set(&key, &value);
    ///     }
    ///     /// Reports an absent (expired) entry as `0` instead of trapping.
    ///     pub fn read(env: Env, key: Symbol) -> i128 {
    ///         env.storage().temporary().get(&key).unwrap_or(0)
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// let client = StoreClient::new(env.env(), &id);
    /// client.set(&symbol_short!("k"), &7);
    ///
    /// // The closure returns a `Result`. After the entry expires the contract
    /// // still reads it gracefully, so the closure yields `Ok` — the assertion
    /// // passes and hands the value back.
    /// let value = env.assert_survives_expiry_result(StorageKind::Temporary, || {
    ///     Ok::<i128, &str>(client.read(&symbol_short!("k")))
    /// });
    /// assert_eq!(value, 0);
    /// # }
    /// ```
    pub fn assert_survives_expiry_result<T, E: std::fmt::Debug>(
        &self,
        kind: StorageKind,
        f: impl FnOnce() -> Result<T, E>,
    ) -> T {
        self.expire(kind);
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
            Ok(Ok(value)) => value,
            Ok(Err(err)) => panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the contract to survive {kind:?} storage expiry gracefully, \
                     but it returned an error: {err:?}"
                ))
            ),
            Err(payload) => panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the contract to survive {kind:?} storage expiry gracefully, \
                     but it panicked: {}",
                    crate::internal::panic_message(payload.as_ref())
                ))
            ),
        }
    }

    fn ttl_of_val(&self, contract: &Address, kind: StorageKind, key_val: &Val) -> u32 {
        self.env().as_contract(contract, || match kind {
            StorageKind::Temporary => self.env().storage().temporary().get_ttl(key_val),
            StorageKind::Persistent => self.env().storage().persistent().get_ttl(key_val),
            StorageKind::Instance => self.env().storage().instance().get_ttl(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contracterror, contractimpl, symbol_short, Symbol};
    use vault::{DataKey, Vault, VaultClient, VaultError};

    #[test]
    fn ttl_of_decreases_as_ledgers_advance() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        let before = env.ttl_of(&id, StorageKind::Persistent, DataKey::Record);
        env.advance_ledgers(10);
        let after = env.ttl_of(&id, StorageKind::Persistent, DataKey::Record);

        assert!(after < before, "expected {after} < {before}");
        assert_eq!(before - after, 10);
    }

    #[test]
    #[should_panic(expected = "expected the call to extend the Persistent TTL")]
    fn assert_bumps_ttl_fails_on_a_contract_that_reads_without_bumping() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_bumps_ttl(&id, StorageKind::Persistent, DataKey::Record, || {
            client.touch_record();
        });
    }

    #[test]
    fn assert_bumps_ttl_passes_on_the_fixed_contract() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_bumps_ttl(&id, StorageKind::Persistent, DataKey::Record, || {
            client.touch_record_checked();
        });
    }

    #[test]
    #[should_panic(expected = "expected the contract to survive")]
    fn assert_survives_expiry_fails_on_a_contract_that_panics_on_missing_entry() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_temp(&42);

        env.assert_survives_expiry(StorageKind::Temporary, || {
            client.read_temp_unchecked();
        });
    }

    #[test]
    fn assert_survives_expiry_passes_on_the_fixed_contract() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_temp(&42);

        env.assert_survives_expiry(StorageKind::Temporary, || {
            assert_eq!(client.read_temp_checked(), 0);
        });
    }

    // --- result-aware survival (issue #128) ------------------------------

    #[test]
    fn result_variant_returns_the_ok_value_after_expiry() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_temp(&42);

        // The contract's guarded read survives expiry and reports the
        // default, so the closure is `Ok` and its value comes back.
        let value = env.assert_survives_expiry_result(StorageKind::Temporary, || {
            Ok::<i128, VaultError>(client.read_temp_checked())
        });
        assert_eq!(value, 0);
    }

    #[test]
    #[should_panic(expected = "returned an error")]
    fn result_variant_fails_when_the_closure_returns_err() {
        let env = TestEnv::new();

        // An `Err` is a failure even though the closure never panicked: a
        // contract that signals a handled missing entry with an error has
        // not survived gracefully.
        env.assert_survives_expiry_result(StorageKind::Temporary, || {
            Err::<(), VaultError>(VaultError::NotInitialized)
        });
    }

    #[test]
    #[should_panic(expected = "but it panicked")]
    fn result_variant_still_fails_when_the_closure_panics() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_temp(&42);

        // The buggy entry point traps on the missing entry; the variant
        // reports that the same way the panic-only assertion does.
        env.assert_survives_expiry_result(StorageKind::Temporary, || {
            Ok::<i128, VaultError>(client.read_temp_unchecked())
        });
    }

    // --- preserving contract error detail (issue #129) -------------------
    //
    // When the closure traps, `assert_survives_expiry` re-reports the panic
    // with its cause, so the failure says *why* the contract did not survive
    // rather than only that it panicked. Two payload shapes matter: the
    // strings `panic!` produces, and the SDK's own error, whose `Debug` form
    // carries the contract error code.
    //
    // The `Failer` fixture below has one entry point returning a typed
    // contract error, so calling it through the panicking (non-`try_`) client
    // method traps with the SDK error `Error(Contract, #1)`.

    #[contracterror]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(u32)]
    enum SlotError {
        Empty = 1,
    }

    #[contract]
    struct Failer;

    #[contractimpl]
    impl Failer {
        pub fn boom(env: Env) -> Result<(), SlotError> {
            let _ = env;
            Err(SlotError::Empty)
        }
    }

    #[test]
    fn assert_survives_expiry_preserves_a_string_panic_payload() {
        let env = TestEnv::new();

        let message = crate::testing::assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
            env.assert_survives_expiry(StorageKind::Temporary, || {
                panic!("contract blew up before reading the entry");
            });
        });

        assert!(
            message.contains("contract blew up before reading the entry"),
            "the panic detail should be preserved, got: {message}"
        );
    }

    #[test]
    fn assert_survives_expiry_preserves_an_sdk_error_panic_payload() {
        let env = TestEnv::new();

        // A payload that is a bare SDK error rather than a string, as a
        // closure could carry with `panic_any`.
        let err: soroban_sdk::Error = SlotError::Empty.into();
        let message = crate::testing::assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
            env.assert_survives_expiry(StorageKind::Temporary, || {
                std::panic::panic_any(err);
            });
        });

        assert!(
            message.contains("Error(Contract, #1)"),
            "the SDK error detail should be preserved, got: {message}"
        );
    }

    #[test]
    fn assert_survives_expiry_preserves_a_contracts_own_error() {
        let env = TestEnv::new();
        let id = env.env().register(Failer, ());
        let client = FailerClient::new(env.env(), &id);

        // The contract signals the missing entry by returning its typed
        // error; the panicking client method turns that into a trap whose
        // message names the contract error.
        let message = crate::testing::assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
            env.assert_survives_expiry(StorageKind::Temporary, || {
                client.boom();
            });
        });

        assert!(
            message.contains("Error(Contract, #1)"),
            "the contract's error code should be preserved, got: {message}"
        );
    }

    // --- the last-live-ledger boundary (issue #126) ----------------------
    //
    // `get_ttl` counts the ledgers left until an entry expires *excluding* the
    // current one, and the host treats an entry as live while
    // `live_until_ledger >= current_sequence`. So the last live ledger is the
    // one where the remaining TTL has fallen to 0: the entry still reads back
    // there, and it is only on the following ledger — where
    // `live_until < current_sequence` — that expiry behavior kicks in.
    //
    // These tests pin that edge for each storage kind by checking the entry
    // BEFORE the boundary, AT it, and AFTER it. The after-behavior differs per
    // kind and is exactly what the tests document:
    //
    //   * Temporary  — dropped on expiry: reads see nothing and `ttl_of`
    //                  panics.
    //   * Persistent — auto-restored on access by the recording test host
    //                  (mirroring on-chain restoration), so the value survives
    //                  and `ttl_of` reports a fresh, positive TTL.
    //   * Instance   — a persistent-durability entry, restored the same way.

    #[test]
    fn temporary_entry_is_readable_at_the_last_live_ledger_and_gone_after() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_temp(&42);

        // Before: TTL remains and the value reads back.
        let start = env.ttl_of(&id, StorageKind::Temporary, DataKey::Temp);
        assert!(start > 1, "precondition: {start} ledgers of TTL remain");
        assert_eq!(client.read_temp_checked(), 42);

        // At: the last live ledger — remaining TTL is 0 and the entry is still
        // live and readable.
        env.advance_ledgers(start);
        assert_eq!(env.ttl_of(&id, StorageKind::Temporary, DataKey::Temp), 0);
        assert_eq!(client.read_temp_checked(), 42);

        // After: one ledger later the entry is gone — the contract's guarded
        // read sees nothing, and even reading the TTL panics.
        env.advance_ledgers(1);
        assert_eq!(client.read_temp_checked(), 0);
        let expired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.ttl_of(&id, StorageKind::Temporary, DataKey::Temp);
        }));
        assert!(
            expired.is_err(),
            "ttl_of should panic once the temporary entry has expired"
        );
    }

    #[test]
    fn persistent_entry_is_readable_at_the_last_live_ledger_and_restored_after() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&7);

        // Before: TTL remains and the value reads back.
        let start = env.ttl_of(&id, StorageKind::Persistent, DataKey::Record);
        assert!(start > 1, "precondition: {start} ledgers of TTL remain");
        assert_eq!(client.touch_record(), 7);

        // At: the last live ledger — remaining TTL is 0 and the entry is still
        // live and readable.
        env.advance_ledgers(start);
        assert_eq!(env.ttl_of(&id, StorageKind::Persistent, DataKey::Record), 0);
        assert_eq!(client.touch_record(), 7);

        // After: the recording test host restores an expired persistent entry
        // on access, so the value survives and the TTL is refreshed rather
        // than lost.
        env.advance_ledgers(1);
        assert_eq!(client.touch_record(), 7);
        let restored = env.ttl_of(&id, StorageKind::Persistent, DataKey::Record);
        assert!(
            restored > 0,
            "a restored persistent entry should have a fresh, positive TTL, got {restored}"
        );
    }

    #[test]
    fn instance_entry_is_live_at_the_last_live_ledger_and_restored_after() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.initialize(&env.address());

        // Before: TTL remains.
        let start = env.ttl_of(&id, StorageKind::Instance, DataKey::Owner);
        assert!(start > 1, "precondition: {start} ledgers of TTL remain");

        // At: the last live ledger — remaining TTL is 0. Reading the TTL is the
        // only way to observe the instance entry without invoking the contract
        // (an invocation bumps the instance TTL), so returning 0 rather than
        // panicking is the liveness proof.
        env.advance_ledgers(start);
        assert_eq!(env.ttl_of(&id, StorageKind::Instance, DataKey::Owner), 0);

        // After: the instance entry carries persistent durability, so it is
        // restored on access and its TTL is refreshed rather than lost.
        env.advance_ledgers(1);
        let restored = env.ttl_of(&id, StorageKind::Instance, DataKey::Owner);
        assert!(
            restored > 0,
            "a restored instance entry should have a fresh, positive TTL, got {restored}"
        );
    }

    // --- named-key TTL snapshots (issue #127) ----------------------------

    #[contract]
    struct Slots;

    #[contractimpl]
    impl Slots {
        pub fn set_temp(env: Env, key: Symbol, value: i128) {
            env.storage().temporary().set(&key, &value);
        }

        pub fn set_persistent(env: Env, key: Symbol, value: i128) {
            env.storage().persistent().set(&key, &value);
        }

        pub fn set_instance(env: Env, key: Symbol, value: i128) {
            env.storage().instance().set(&key, &value);
        }

        /// Extends `key` well past the TTL a fresh entry gets, so a snapshot
        /// taken before and after shows the bump.
        pub fn bump_temp(env: Env, key: Symbol) {
            env.storage().temporary().extend_ttl(&key, 100, 1_000);
        }
    }

    #[test]
    fn snapshot_reports_each_named_persistent_key_in_order() {
        let env = TestEnv::new();
        let id = env.env().register(Slots, ());
        let client = SlotsClient::new(env.env(), &id);
        client.set_persistent(&symbol_short!("a"), &1);
        client.set_persistent(&symbol_short!("b"), &2);

        let snapshot = env.ttl_snapshot(
            &id,
            StorageKind::Persistent,
            [("a", symbol_short!("a")), ("b", symbol_short!("b"))],
        );

        assert_eq!(snapshot.len(), 2);
        // Names come back in the order they were supplied...
        assert_eq!(snapshot[0].0, "a");
        assert_eq!(snapshot[1].0, "b");
        // ...and each TTL matches the single-key read the snapshot wraps.
        assert_eq!(
            snapshot[0].1,
            env.ttl_of(&id, StorageKind::Persistent, symbol_short!("a"))
        );
        assert_eq!(
            snapshot[1].1,
            env.ttl_of(&id, StorageKind::Persistent, symbol_short!("b"))
        );
    }

    #[test]
    fn snapshot_shows_only_the_bumped_temporary_key_changing() {
        let env = TestEnv::new();
        let id = env.env().register(Slots, ());
        let client = SlotsClient::new(env.env(), &id);
        client.set_temp(&symbol_short!("a"), &1);
        client.set_temp(&symbol_short!("b"), &2);

        let keys = [("a", symbol_short!("a")), ("b", symbol_short!("b"))];
        let before = env.ttl_snapshot(&id, StorageKind::Temporary, keys.clone());
        client.bump_temp(&symbol_short!("a"));
        let after = env.ttl_snapshot(&id, StorageKind::Temporary, keys);

        assert!(after[0].1 > before[0].1, "the bumped key's TTL should grow");
        assert_eq!(
            after[1].1, before[1].1,
            "the untouched key's TTL should not move"
        );
    }

    #[test]
    fn instance_snapshot_reports_one_ttl_for_every_name() {
        let env = TestEnv::new();
        let id = env.env().register(Slots, ());
        let client = SlotsClient::new(env.env(), &id);
        client.set_instance(&symbol_short!("a"), &1);
        client.set_instance(&symbol_short!("b"), &2);

        let snapshot = env.ttl_snapshot(
            &id,
            StorageKind::Instance,
            [("owner", symbol_short!("a")), ("balance", symbol_short!("b"))],
        );

        // Instance storage is one entry per contract, so the key is ignored
        // and every name reports the same TTL.
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].1, snapshot[1].1);
        assert_eq!(
            snapshot[0].1,
            env.ttl_of(&id, StorageKind::Instance, symbol_short!("a"))
        );
    }

    #[test]
    #[should_panic]
    fn snapshot_panics_when_a_named_key_is_missing() {
        let env = TestEnv::new();
        let id = env.env().register(Slots, ());

        // `nope` was never written, so the snapshot fails the same way
        // `ttl_of` would rather than silently reporting a bogus TTL.
        env.ttl_snapshot(&id, StorageKind::Persistent, [("nope", symbol_short!("nope"))]);
    }
}
