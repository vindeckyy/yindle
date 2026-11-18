#![no_main]
//! Decode arbitrary bytes as IPP under default, strict, and tight `DecodeLimits`;
//! a panic or limit bypass is a bug. On a clean decode we also re-encode and
//! re-decode to exercise the round-trip.

use ipp_codec::DecodeLimits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let tight = DecodeLimits {
        max_groups: 4,
        max_attributes: 8,
        max_values: 16,
        max_string_len: 32,
        max_total_value_bytes: 64,
        max_collection_depth: 2,
    };
    let strict = DecodeLimits::strict();

    let tight_res = ipp_codec::decode_with_limits(data, &tight);
    let strict_res = ipp_codec::decode_with_limits(data, &strict);
    let default_res = ipp_codec::decode(data);

    // Monotonicity: any message accepted under tighter limits must also decode
    // identically under looser limits.
    if let Ok((msg_tight, consumed_tight)) = &tight_res {
        assert!(*consumed_tight <= data.len());
        assert!(msg_tight.groups.len() <= tight.max_groups);
        let (msg_strict, consumed_strict) = strict_res
            .as_ref()
            .expect("tight DecodeLimits succeeded but strict failed");
        assert_eq!(msg_tight, msg_strict);
        assert_eq!(consumed_tight, consumed_strict);
    }

    if let Ok((msg_strict, consumed_strict)) = &strict_res {
        assert!(*consumed_strict <= data.len());
        assert!(msg_strict.groups.len() <= strict.max_groups);
        let (msg_def, consumed_def) = default_res
            .as_ref()
            .expect("strict DecodeLimits succeeded but default failed");
        assert_eq!(msg_strict, msg_def);
        assert_eq!(consumed_strict, consumed_def);
        if let Ok(bytes) = ipp_codec::encode(msg_strict) {
            if let Ok((_, consumed2)) = ipp_codec::decode_with_limits(&bytes, &strict) {
                assert!(consumed2 <= bytes.len());
            }
        }
    }

    if let Ok((msg, consumed)) = default_res {
        assert!(consumed <= data.len());
        if let Ok(bytes) = ipp_codec::encode(&msg) {
            if let Ok((_, consumed2)) = ipp_codec::decode(&bytes) {
                assert!(consumed2 <= bytes.len());
            }
        }
    }
});
