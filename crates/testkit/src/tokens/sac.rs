use std::borrow::Borrow;
use std::cell::Cell;

use soroban_sdk::testutils::{MockAuth, MockAuthInvoke};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::xdr::{ScErrorCode, ScErrorType};
use soroban_sdk::{Address, Env, Error, IntoVal, InvokeError};

use crate::core::{TestEnv, TestkitError};

/// The decimal precision every Stellar Asset Contract uses.
///
/// This is fixed by the protocol (the classic Stellar asset precision), not
/// something a deployer can choose. Verified against soroban-sdk 27.0.6:
/// `register_stellar_asset_contract_v2` takes no decimals parameter, and a
/// freshly deployed SAC's own `decimals()` always returns 7.
///
/// # Example
///
/// ```
/// use soroban_testkit::prelude::*;
///
/// let env = TestEnv::new();
/// assert_eq!(env.token().decimals(), SAC_DECIMALS);
/// ```
pub const SAC_DECIMALS: u32 = 7;

/// SAC `ContractError::BalanceError` code, returned when a transfer would
/// take the sender's balance below zero.
const SAC_BALANCE_ERROR_CODE: u32 = 10;

/// The SDK surfaces a failed `Address::require_auth` on a SAC transfer as a
/// host context error rather than a contract error.
fn sac_missing_auth_error() -> Error {
    Error::from_type_and_code(ScErrorType::Context, ScErrorCode::InvalidAction)
}

type TransferResult = Result<(), Result<Error, InvokeError>>;

fn describe_transfer_result(result: &TransferResult) -> String {
    match result {
        Ok(()) => "the transfer succeeded".to_owned(),
        Err(Ok(error)) => format!("the transfer failed with {error:?}"),
        Err(Err(invoke_error)) => format!("the invocation failed with {invoke_error:?}"),
    }
}

/// A deployed Stellar Asset Contract test double, with one-line mint/balance
/// helpers so tests don't hand-roll SAC setup boilerplate.
pub struct TestToken {
    env: Env,
    address: Address,
    admin: Address,
    total_tracked: Cell<i128>,
}

impl TestToken {
    fn new(env: &Env, admin: Address) -> Self {
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        Self {
            env: env.clone(),
            address: sac.address(),
            admin,
            total_tracked: Cell::new(0),
        }
    }

    /// The admin address this token was registered with.
    ///
    /// Use this when composing auth expectations, e.g. for `mint`,
    /// `set_authorized`, or `set_admin`, which require the admin's auth.
    pub fn admin(&self) -> &Address {
        &self.admin
    }

    /// The admin address as an owned value, for APIs that take `Address` by value.
    pub fn admin_address(&self) -> Address {
        self.admin.clone()
    }

    /// The token contract's address.
    pub fn address(&self) -> Address {
        self.address.clone()
    }

    /// The token's decimal precision. Always `7`, fixed by the protocol.
    pub fn decimals(&self) -> u32 {
        SAC_DECIMALS
    }

    /// Mint `amount` **whole units** to `to` (converted internally to base
    /// units, i.e. `amount * 10^decimals`).
    ///
    /// A zero `amount` is allowed and changes nothing (see
    /// [`TestToken::mint_raw`]).
    ///
    /// The largest whole-unit amount that converts safely is
    /// `i128::MAX / 10^decimals`.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if `amount` is negative, or if
    /// the conversion to base units would overflow `i128`; use
    /// [`TestToken::mint_raw`] for amounts already in base units.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.mint(&alice, 100);
    /// token.assert_balance(&alice, 1_000_000_000); // 100 * 10^7
    /// ```
    pub fn mint(&self, to: &Address, amount: i128) {
        if amount < 0 {
            panic!(
                "{}",
                TestkitError::Misuse(format!(
                    "mint({amount}) is negative; a mint amount must be zero or positive"
                ))
            );
        }
        let scale = 10i128.pow(self.decimals());
        let raw = amount.checked_mul(scale).unwrap_or_else(|| {
            panic!(
                "{}",
                TestkitError::Misuse(format!(
                    "mint({amount}) overflows i128 once converted to base units at {} \
                     decimals; use mint_raw for amounts already in base units",
                    self.decimals()
                ))
            )
        });
        self.mint_raw(to, raw);
    }

    /// Mint `amount` **base units** (stroops) to `to`, with no unit
    /// conversion.
    ///
    /// A zero `amount` is allowed: the Stellar Asset Contract accepts a zero
    /// mint as a no-op, so balances and [`TestToken::total_tracked`] stay as
    /// they were. A negative `amount` is rejected before the token host is
    /// invoked.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if `amount` is negative, or if
    /// adding it to [`TestToken::total_tracked`] would overflow `i128`. In
    /// both cases nothing is minted and the tracked total is unchanged.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.mint_raw(&alice, 42);
    /// token.assert_balance(&alice, 42);
    /// ```
    pub fn mint_raw(&self, to: &Address, amount: i128) {
        if amount < 0 {
            panic!(
                "{}",
                TestkitError::Misuse(format!(
                    "mint_raw({amount}) is negative; a mint amount must be zero or positive"
                ))
            );
        }
        // Work out the new tracked total first, so an overflow is reported
        // before anything is minted and the token and the tracker never
        // disagree.
        let new_total = self
            .total_tracked
            .get()
            .checked_add(amount)
            .unwrap_or_else(|| {
                panic!(
                    "{}",
                    TestkitError::Misuse(format!(
                    "mint_raw({amount}) would overflow total_tracked (currently {}); the sum of \
                     all mints must stay within i128::MAX",
                    self.total_tracked.get()
                ))
                )
            });
        StellarAssetClient::new(&self.env, &self.address)
            .mock_auths(&[MockAuth {
                address: &self.admin,
                invoke: &MockAuthInvoke {
                    contract: &self.address,
                    fn_name: "mint",
                    args: (to.clone(), amount).into_val(&self.env),
                    sub_invokes: &[],
                },
            }])
            .mint(to, &amount);
        self.total_tracked.set(new_total);
    }

    /// The base-unit balance of `of`.
    pub fn balance(&self, of: &Address) -> i128 {
        TokenClient::new(&self.env, &self.address).balance(of)
    }

    /// Assert that `of`'s base-unit balance equals `expected`.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] showing the token
    /// address, recipient address, and expected and actual balances if they
    /// differ.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.mint_raw(&alice, 10);
    /// token.assert_balance(&alice, 10);
    /// ```
    pub fn assert_balance(&self, of: &Address, expected: i128) {
        let actual = self.balance(of);
        if actual != expected {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected balance of {of:?} on token {:?} to be {expected}, found {actual}",
                    self.address
                ))
            );
        }
    }

    fn try_transfer(
        &self,
        from: &Address,
        to: &Address,
        amount: i128,
        authorize_from: bool,
    ) -> TransferResult {
        let client = TokenClient::new(&self.env, &self.address);
        let result = if authorize_from {
            client
                .mock_auths(&[MockAuth {
                    address: from,
                    invoke: &MockAuthInvoke {
                        contract: &self.address,
                        fn_name: "transfer",
                        args: (from.clone(), to.clone(), amount).into_val(&self.env),
                        sub_invokes: &[],
                    },
                }])
                .try_transfer(from, soroban_sdk::MuxedAddress::from(to.clone()), &amount)
        } else {
            client.try_transfer(from, soroban_sdk::MuxedAddress::from(to.clone()), &amount)
        };
        result.map(|converted| converted.expect("a SAC transfer returns no value to convert"))
    }

    /// Assert that a transfer fails with the SAC's insufficient-balance
    /// error, `Error(Contract, #10)` (`ContractError::BalanceError`).
    ///
    /// This helper mocks `from`'s authorization for the single call so the
    /// failure comes from the balance check, not from a missing signature.
    /// Use [`TestToken::assert_transfer_fails_with_unauthorized`] for the
    /// missing-signature case. Amounts are base units, as with
    /// [`TestToken::balance`]; no whole-unit conversion is performed.
    ///
    /// # Panics
    ///
    /// Panics with [`TestkitError::AssertionFailed`] if the transfer succeeds
    /// or returns any error other than the insufficient-balance error.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// let bob = env.address();
    /// token.mint_raw(&alice, 10);
    ///
    /// token.assert_transfer_fails_with_insufficient_balance(&alice, &bob, 11);
    /// token.assert_balance(&alice, 10); // the failed transfer changed nothing
    /// token.assert_balance(&bob, 0);
    /// ```
    pub fn assert_transfer_fails_with_insufficient_balance(
        &self,
        from: impl Borrow<Address>,
        to: impl Borrow<Address>,
        amount: i128,
    ) {
        let result = self.try_transfer(from.borrow(), to.borrow(), amount, true);
        let expected = Error::from_contract_error(SAC_BALANCE_ERROR_CODE);
        if !matches!(&result, Err(Ok(error)) if *error == expected) {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected transfer of {amount} from {:?} to {:?} to fail with SAC \
                     insufficient-balance error {expected:?}, but {}",
                    from.borrow(),
                    to.borrow(),
                    describe_transfer_result(&result)
                ))
            );
        }
    }

    /// Assert that a transfer fails because `from` did not authorize it.
    ///
    /// The call is made without any mocked authorization, so the SDK reports
    /// the failing `require_auth` as `Error(Context, InvalidAction)`. This is
    /// the SDK's representation of an unauthorized SAC transfer; it is not
    /// the SAC's contract error #4. Amounts are base units.
    ///
    /// # Panics
    ///
    /// Panics with [`TestkitError::AssertionFailed`] if the transfer succeeds
    /// or returns any error other than the missing-authorization error.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// let bob = env.address();
    /// token.mint_raw(&alice, 10);
    ///
    /// token.assert_transfer_fails_with_unauthorized(&alice, &bob, 1);
    /// token.assert_balance(&alice, 10);
    /// token.assert_balance(&bob, 0);
    /// ```
    pub fn assert_transfer_fails_with_unauthorized(
        &self,
        from: impl Borrow<Address>,
        to: impl Borrow<Address>,
        amount: i128,
    ) {
        let result = self.try_transfer(from.borrow(), to.borrow(), amount, false);
        let expected = sac_missing_auth_error();
        if !matches!(&result, Err(Ok(error)) if *error == expected) {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected transfer of {amount} from {:?} to {:?} to fail with \
                     missing-authorization error {expected:?}, but {}",
                    from.borrow(),
                    to.borrow(),
                    describe_transfer_result(&result)
                ))
            );
        }
    }

    /// Alias for [`TestToken::assert_transfer_fails_with_insufficient_balance`].
    pub fn assert_transfer_insufficient_balance(
        &self,
        from: impl Borrow<Address>,
        to: impl Borrow<Address>,
        amount: i128,
    ) {
        self.assert_transfer_fails_with_insufficient_balance(from, to, amount);
    }

    /// Alias for [`TestToken::assert_transfer_fails_with_unauthorized`].
    pub fn assert_transfer_unauthorized(
        &self,
        from: impl Borrow<Address>,
        to: impl Borrow<Address>,
        amount: i128,
    ) {
        self.assert_transfer_fails_with_unauthorized(from, to, amount);
    }

    /// Alias for [`TestToken::assert_transfer_fails_with_insufficient_balance`].
    pub fn assert_insufficient_balance_transfer(
        &self,
        from: impl Borrow<Address>,
        to: impl Borrow<Address>,
        amount: i128,
    ) {
        self.assert_transfer_fails_with_insufficient_balance(from, to, amount);
    }

    /// Alias for [`TestToken::assert_transfer_fails_with_unauthorized`].
    pub fn assert_unauthorized_transfer(
        &self,
        from: impl Borrow<Address>,
        to: impl Borrow<Address>,
        amount: i128,
    ) {
        self.assert_transfer_fails_with_unauthorized(from, to, amount);
    }

    /// Total base units minted through this `TestToken` (via
    /// [`TestToken::mint`] or [`TestToken::mint_raw`]) across every
    /// recipient — for supply-conservation assertions.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// token.mint_raw(&env.address(), 10);
    /// token.mint_raw(&env.address(), 5);
    /// assert_eq!(token.total_tracked(), 15);
    /// ```
    pub fn total_tracked(&self) -> i128 {
        self.total_tracked.get()
    }
}

impl TestEnv {
    /// Deploy a Stellar Asset Contract with the standard 7 decimals.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// assert_eq!(token.decimals(), 7);
    /// ```
    pub fn token(&self) -> TestToken {
        let admin = self.address();
        TestToken::new(self.env(), admin)
    }

    /// Deploy a Stellar Asset Contract, asserting it uses `decimals`.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if `decimals != 7`. Stellar
    /// Asset Contracts fix their decimal precision at 7 (the classic
    /// Stellar asset precision) — verified against soroban-sdk 27.0.6,
    /// where `register_stellar_asset_contract_v2` takes no decimals
    /// parameter. This method exists so a test that expects a specific
    /// precision fails loudly if that ever changes, rather than silently
    /// assuming it.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token_with_decimals(7);
    /// assert_eq!(token.decimals(), 7);
    /// ```
    pub fn token_with_decimals(&self, decimals: u32) -> TestToken {
        if decimals != SAC_DECIMALS {
            panic!(
                "{}",
                TestkitError::Misuse(format!(
                    "token_with_decimals({decimals}): Stellar Asset Contracts fix decimals at \
                     {SAC_DECIMALS} and cannot be deployed with a different precision; use \
                     token() for the standard {SAC_DECIMALS}-decimal token"
                ))
            );
        }
        self.token()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::assert_panics_with_code;
    use soroban_sdk::{contract, contractimpl};

    #[test]
    fn token_is_immediately_usable_for_transfers() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        token.mint_raw(&alice, 100);

        TokenClient::new(env.env(), &token.address())
            .mock_auths(&[MockAuth {
                address: &alice,
                invoke: &MockAuthInvoke {
                    contract: &token.address(),
                    fn_name: "transfer",
                    args: (alice.clone(), bob.clone(), 30_i128).into_val(env.env()),
                    sub_invokes: &[],
                },
            }])
            .transfer(&alice, soroban_sdk::MuxedAddress::from(bob.clone()), &30);

        token.assert_balance(&alice, 70);
        token.assert_balance(&bob, 30);
    }

    #[test]
    fn insufficient_balance_helper_matches_the_sac_error_and_leaves_balances_unchanged() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        token.mint_raw(&alice, 10);

        token.assert_transfer_fails_with_insufficient_balance(&alice, &bob, 11);
        token.assert_balance(&alice, 10);
        token.assert_balance(&bob, 0);
    }

    #[test]
    fn insufficient_balance_helper_handles_a_zero_balance() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();

        token.assert_transfer_fails_with_insufficient_balance(&alice, &bob, 1);
        token.assert_balance(&alice, 0);
        token.assert_balance(&bob, 0);
    }

    #[test]
    fn unauthorized_helper_matches_the_missing_auth_error_and_leaves_balances_unchanged() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        token.mint_raw(&alice, 10);

        token.assert_transfer_fails_with_unauthorized(&alice, &bob, 1);
        token.assert_balance(&alice, 10);
        token.assert_balance(&bob, 0);
    }

    #[test]
    fn unauthorized_helper_rejects_a_transfer_that_would_succeed() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        token.mint_raw(&alice, 10);
        env.env().mock_all_auths();

        let message = assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
            token.assert_transfer_fails_with_unauthorized(&alice, &bob, 1);
        });
        assert!(message.contains("the transfer succeeded"), "{message}");
        token.assert_balance(&alice, 9);
        token.assert_balance(&bob, 1);
    }

    #[test]
    fn insufficient_balance_helper_rejects_a_different_contract_error() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();

        // A negative amount is rejected with NegativeAmountError (#8), not
        // BalanceError (#10), so the helper must not accept it.
        let message = assert_panics_with_code("TESTKIT_ASSERTION_FAILED", || {
            token.assert_transfer_fails_with_insufficient_balance(&alice, &bob, -1);
        });
        assert!(message.contains("Error(Contract, #8)"), "{message}");
    }

    #[test]
    fn transfer_failure_helper_aliases_delegate_to_the_primaries() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        token.mint_raw(&alice, 10);

        token.assert_transfer_insufficient_balance(&alice, &bob, 11);
        token.assert_insufficient_balance_transfer(&alice, &bob, 11);
        token.assert_transfer_unauthorized(&alice, &bob, 1);
        token.assert_unauthorized_transfer(&alice, &bob, 1);
    }

    #[test]
    fn mint_converts_whole_units_at_seven_decimals() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        token.mint(&alice, 100);
        token.assert_balance(&alice, 1_000_000_000);
    }

    #[test]
    fn mint_and_mint_raw_disagree_by_exactly_ten_pow_decimals() {
        let env = TestEnv::new();
        let token = env.token();
        let a = env.address();
        let b = env.address();

        token.mint(&a, 1);
        token.mint_raw(&b, 1);

        assert_eq!(token.balance(&a), token.balance(&b) * 10i128.pow(7));
    }

    #[test]
    #[should_panic(expected = "token_with_decimals(6)")]
    fn token_with_decimals_rejects_non_seven() {
        let env = TestEnv::new();
        let _ = env.token_with_decimals(6);
    }

    #[test]
    fn total_tracked_sums_every_mint() {
        let env = TestEnv::new();
        let token = env.token();
        token.mint_raw(&env.address(), 10);
        token.mint(&env.address(), 1);
        assert_eq!(token.total_tracked(), 10 + 10i128.pow(7));
    }

    // ── Mint edge cases (#90, #92, #94, #97) ────────────────────────────────

    #[test]
    fn zero_mint_leaves_balance_and_tracked_supply_unchanged() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        token.mint_raw(&alice, 0);
        token.assert_balance(&alice, 0);
        assert_eq!(token.total_tracked(), 0);

        token.mint(&alice, 0);
        token.assert_balance(&alice, 0);
        assert_eq!(token.total_tracked(), 0);

        // A zero mint after a real one changes nothing either.
        token.mint_raw(&alice, 25);
        token.mint_raw(&alice, 0);
        token.assert_balance(&alice, 25);
        assert_eq!(token.total_tracked(), 25);
    }

    #[test]
    #[should_panic(expected = "mint_raw(-1) is negative")]
    fn mint_raw_rejects_a_negative_amount() {
        let env = TestEnv::new();
        env.token().mint_raw(&env.address(), -1);
    }

    #[test]
    fn rejected_negative_mint_raw_does_not_change_tracked_supply() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        token.mint_raw(&alice, 10);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            token.mint_raw(&alice, -5);
        }));
        assert!(result.is_err());
        token.assert_balance(&alice, 10);
        assert_eq!(token.total_tracked(), 10);
    }

    #[test]
    #[should_panic(expected = "mint(-3) is negative")]
    fn mint_rejects_a_negative_whole_unit_amount() {
        let env = TestEnv::new();
        env.token().mint(&env.address(), -3);
    }

    #[test]
    fn mint_accepts_the_largest_safe_whole_unit_amount() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let largest = i128::MAX / 10i128.pow(7);

        token.mint(&alice, largest);
        token.assert_balance(&alice, largest * 10i128.pow(7));
        assert_eq!(token.total_tracked(), largest * 10i128.pow(7));
    }

    #[test]
    #[should_panic(expected = "overflows i128 once converted to base units")]
    fn mint_rejects_one_whole_unit_past_the_largest_safe_amount() {
        let env = TestEnv::new();
        let past = i128::MAX / 10i128.pow(7) + 1;
        env.token().mint(&env.address(), past);
    }

    #[test]
    #[should_panic(expected = "would overflow total_tracked")]
    fn total_tracked_overflow_is_reported_not_wrapped() {
        let env = TestEnv::new();
        let token = env.token();
        token.mint_raw(&env.address(), i128::MAX);
        token.mint_raw(&env.address(), 1);
    }

    #[test]
    fn total_tracked_can_reach_i128_max_exactly() {
        let env = TestEnv::new();
        let token = env.token();
        token.mint_raw(&env.address(), i128::MAX - 5);
        token.mint_raw(&env.address(), 5);
        assert_eq!(token.total_tracked(), i128::MAX);
    }

    #[test]
    fn overflowing_mint_leaves_tracked_supply_and_balance_untouched() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        token.mint_raw(&alice, i128::MAX - 1);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            token.mint_raw(&alice, 2);
        }));
        assert!(result.is_err());
        assert_eq!(token.total_tracked(), i128::MAX - 1);
        token.assert_balance(&alice, i128::MAX - 1);
    }

    #[contract]
    struct Wallet;

    #[contractimpl]
    impl Wallet {
        pub fn send(env: Env, token: Address, from: Address, to: Address, amount: i128) {
            TokenClient::new(&env, &token).transfer(
                &from,
                soroban_sdk::MuxedAddress::from(to),
                &amount,
            );
        }

        pub fn spend(env: Env, token: Address, from: Address, amount: i128) {
            TokenClient::new(&env, &token).burn(&from, &amount);
        }

        pub fn allow(
            env: Env,
            token: Address,
            from: Address,
            spender: Address,
            amount: i128,
            live_until: u32,
        ) {
            TokenClient::new(&env, &token).approve(&from, &spender, &amount, &live_until);
        }
    }

    #[test]
    fn works_with_a_contract_that_transfers_burns_and_approves() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        let spender = env.address();
        token.mint_raw(&alice, 1_000);

        env.env().mock_all_auths_allowing_non_root_auth();
        let wallet_id = env.env().register(Wallet, ());
        let wallet = WalletClient::new(env.env(), &wallet_id);

        wallet.send(&token.address(), &alice, &bob, &300);
        token.assert_balance(&alice, 700);
        token.assert_balance(&bob, 300);

        wallet.spend(&token.address(), &alice, &200);
        token.assert_balance(&alice, 500);

        wallet.allow(&token.address(), &alice, &spender, &50, &1_000);
        let allowance = TokenClient::new(env.env(), &token.address()).allowance(&alice, &spender);
        assert_eq!(allowance, 50);
    }

    #[test]
    fn assert_balance_failure_includes_token_and_recipient_context() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        token.mint_raw(&alice, 42);

        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            token.assert_balance(&alice, 100);
        }))
        .expect_err("expected assert_balance to panic on mismatch");

        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&str>().copied())
            .expect("panic payload should be a string");

        assert_eq!(
            msg,
            format!(
                "assertion failed: expected balance of {alice:?} on token {:?} to be 100, found 42",
                token.address()
            )
        );
    }
}
