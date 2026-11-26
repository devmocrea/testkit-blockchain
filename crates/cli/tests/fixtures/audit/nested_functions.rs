//! Audit fixture for nested functions and nested arithmetic (#146).
//!
//! Parsed by `soroban-testkit audit` in `tests/integration.rs`; it is not
//! compiled. Each finding must be reported exactly once, attributed to the
//! function whose own body contains it. Expected findings are marked below.

pub struct Contract;

// An entry-point block, so `missing-require-auth` applies to its `pub fn`s (#134).
#[contractimpl]
impl Contract {
    // missing-require-auth: the nested helper's require_auth
    // authorizes the helper, not `outer`.
    pub fn outer(env: Env, owner: Address, a: i128, b: i128, c: i128) -> i128 {
        // missing-ttl-bump belongs to `helper` only.
        fn helper(env: Env, user: Address) -> i128 {
            user.require_auth();
            let stored: i128 = env.storage().persistent().get(&KEY).unwrap();
            // unchecked-i128-arithmetic, reported for `helper` only.
            stored * 2i128
        }
        // unchecked-i128-arithmetic: one source expression, even
        // though it parses as `(a + b) + c`.
        let total = a + b + c;
        total
    }

    // Two separate expressions, so two findings: the outer `x + ...` and
    // the call argument `y - 1i128`.
    pub fn separate(x: i128, y: i128) -> i128 {
        x + compute(
            y - 1i128,
        )
    }
}
