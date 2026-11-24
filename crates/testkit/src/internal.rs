//! Small helpers shared across modules that are not part of the public API.

use std::any::Any;

/// Extract the message from a caught panic payload.
///
/// Panics are how assertion helpers report failures, so helpers that catch
/// a closure's panic (and re-report it with context) need to read the
/// payload. Two payload shapes are rendered, and anything else gets a
/// placeholder rather than being dropped:
///
/// * `panic!` produces either a `&'static str` or a formatted `String`, so
///   those are read verbatim.
/// * An SDK error carried as a payload — [`soroban_sdk::Error`] (the error a
///   contract returns) or [`soroban_sdk::testutils::HostError`] (the outer
///   host error the SDK escalates to a panic) — is rendered through its
///   `Debug` form, the same way the host formats an escalated error. This
///   keeps the contract error detail (for example `Error(Contract, #1)`) in
///   the message instead of collapsing it to the placeholder.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(err) = payload.downcast_ref::<soroban_sdk::Error>() {
        format!("{err:?}")
    } else if let Some(err) = payload.downcast_ref::<soroban_sdk::testutils::HostError>() {
        format!("{err:?}")
    } else {
        "<non-string panic payload>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_string_payload_shapes_and_rejects_others() {
        let owned: Box<dyn Any + Send> = Box::new(String::from("owned"));
        let borrowed: Box<dyn Any + Send> = Box::new("borrowed");
        let other: Box<dyn Any + Send> = Box::new(7_u8);
        assert_eq!(panic_message(owned.as_ref()), "owned");
        assert_eq!(panic_message(borrowed.as_ref()), "borrowed");
        assert_eq!(panic_message(other.as_ref()), "<non-string panic payload>");
    }

    #[test]
    fn renders_sdk_error_payloads_instead_of_dropping_them() {
        let contract_error = (
            soroban_sdk::xdr::ScErrorType::Contract,
            soroban_sdk::xdr::ScErrorCode::InvalidAction,
        );

        // The error a contract returns (what a `contracterror` code becomes).
        let error: Box<dyn Any + Send> = Box::new(soroban_sdk::Error::from(contract_error));
        let message = panic_message(error.as_ref());
        assert!(
            message.contains("Error(Contract"),
            "an SDK error payload should keep its contract error detail, got: {message}"
        );

        // The outer host error the SDK escalates to a panic.
        let host: Box<dyn Any + Send> =
            Box::new(soroban_sdk::testutils::HostError::from(contract_error));
        let message = panic_message(host.as_ref());
        assert!(
            message.contains("Error(Contract"),
            "a host error payload should keep its contract error detail, got: {message}"
        );
    }
}
