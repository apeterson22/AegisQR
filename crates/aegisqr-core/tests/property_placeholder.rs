#[test]
fn property_placeholder_deterministic_encoding() {
    // Placeholder for proptest/quickcheck expansion in future PRs.
    let a = serde_cbor::to_vec(&("aegis", 1u8)).unwrap();
    let b = serde_cbor::to_vec(&("aegis", 1u8)).unwrap();
    assert_eq!(a, b);
}
