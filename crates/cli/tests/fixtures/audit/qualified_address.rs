//! Audit fixture for qualified and aliased Address parameter types (#137).

use soroban_sdk::Address as AccountId;
use soroban_sdk::Address as UserAddress;

type ClientAddress = soroban_sdk::Address;
type AliasOfAlias = AccountId;

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn raw_address(a: Address) {}
    pub fn qualified_sdk(b: soroban_sdk::Address) {}
    pub fn aliased_import(c: AccountId) {}
    pub fn aliased_grouped_import(d: UserAddress) {}
    pub fn aliased_type(e: ClientAddress) {}
    pub fn transitive_alias(f: AliasOfAlias) {}
}
