//! # ipp-codec
//!
//! IPP (Internet Printing Protocol) wire codec and message model with
//! libcups-compatible encoding semantics.
//!
//! This crate is the foundation of the cupsd rewrite: every HTTP request
//! body on port 631 is an IPP message, and the byte-level details matter —
//! delimiter-group ordering, separator re-emission, `memberAttrName`
//! collection framing, out-of-band tags, `1setOf` value-tag coercion, and
//! the CUPS-private operation IDs are all preserved exactly.
//!
//! ```rust
//! use ipp_codec::{decode, encode, Attribute, Group, IppMessage, Text, Value, tags, ops};
//!
//! let mut msg = IppMessage::new(ops::status::OK);
//! msg.request_id = 42;
//! let mut op = Group::new(tags::OPERATION);
//! op.attributes.push(Attribute::new(
//!     "attributes-charset",
//!     tags::CHARSET,
//!     vec![Value::Charset(Text::from("utf-8"))],
//! ));
//! msg.groups.push(op);
//!
//! let bytes = encode(&msg).unwrap();
//! let (back, doc_offset) = decode(&bytes).unwrap();
//! assert_eq!(doc_offset, bytes.len());
//! assert_eq!(back.code, ops::status::OK);
//! ```

pub mod codec;
pub mod error;
pub mod model;
pub mod ops;
pub mod tags;

pub use codec::{
    decode, decode_with_limits, encode, DecodeLimits, MAX_ATTRIBUTES, MAX_COLLECTION_DEPTH,
    MAX_GROUPS, MAX_NAME_LEN, MAX_STRING_LEN, MAX_TOTAL_VALUE_BYTES, MAX_VALUES, MAX_VALUE_LEN,
};
pub use error::CodecError;
pub use model::{Attribute, Group, IppMessage, Text, Value};

#[cfg(test)]
mod tests {
    use super::*;

    fn op_attr(name: &str, tag: u8, values: Vec<Value>) -> Attribute {
        Attribute::new(name, tag, values)
    }

    #[test]
    fn header_only_message() {
        let mut msg = IppMessage::new(ops::op::GET_PRINTER_ATTRIBUTES);
        msg.request_id = 7;
        let bytes = encode(&msg).unwrap();
        assert_eq!(bytes.len(), 9);
        assert_eq!(&bytes[..8], &[2, 0, 0, 0x0b, 0, 0, 0, 7]);
        assert_eq!(bytes[8], tags::END);

        let (back, off) = decode(&bytes).unwrap();
        assert_eq!(off, 9);
        assert_eq!(back.version, (2, 0));
        assert_eq!(back.code, ops::op::GET_PRINTER_ATTRIBUTES);
        assert_eq!(back.request_id, 7);
        assert_eq!(back.groups, [] as [model::Group; 0]);
    }

    #[test]
    fn simple_roundtrip() {
        let mut msg = IppMessage::new(ops::op::GET_PRINTER_ATTRIBUTES);
        msg.request_id = 1;
        let mut op = Group::new(tags::OPERATION);
        op.attributes.extend([
            op_attr(
                "attributes-charset",
                tags::CHARSET,
                vec![Value::Charset("utf-8".into())],
            ),
            op_attr(
                "attributes-natural-language",
                tags::LANGUAGE,
                vec![Value::NaturalLanguage("en".into())],
            ),
            op_attr(
                "printer-uri",
                tags::URI,
                vec![Value::Uri("ipp://localhost/printers/x".into())],
            ),
            op_attr(
                "requested-attributes",
                tags::KEYWORD,
                vec![
                    Value::Keyword("all".into()),
                    Value::Keyword("media-col-database".into()),
                ],
            ),
            op_attr("limit", tags::INTEGER, vec![Value::Integer(50)]),
            op_attr("first-value", tags::BOOLEAN, vec![Value::Boolean(true)]),
        ]);
        msg.groups.push(op);

        let bytes = encode(&msg).unwrap();
        let (back, off) = decode(&bytes).unwrap();
        assert_eq!(off, bytes.len());
        assert_eq!(back, msg);
    }

    #[test]
    fn byte_exact_known_packet() {
        // A minimal Get-Printer-Attributes request, hand-encoded per
        // RFC 8010 to verify exact byte layout.
        let mut expected = vec![
            2,
            0, // version 2.0
            0,
            0x0b, // Get-Printer-Attributes
            0,
            0,
            0,
            1, // request-id 1
            tags::OPERATION,
            tags::CHARSET,
            0,
            18, // namelen 18
        ];
        expected.extend_from_slice(b"attributes-charset");
        expected.extend_from_slice(&[0, 5]); // vallen 5
        expected.extend_from_slice(b"utf-8");
        expected.push(tags::END);

        let (msg, off) = decode(&expected).unwrap();
        assert_eq!(off, expected.len());
        assert_eq!(msg.code, ops::op::GET_PRINTER_ATTRIBUTES);
        let attr = msg.find(tags::OPERATION, "attributes-charset").unwrap();
        assert_eq!(attr.values, vec![Value::Charset("utf-8".into())]);
    }

    #[test]
    fn collection_roundtrip() {
        // media-col={media-size={x-dimension=21000 y-dimension=29700} media-type=stationery}
        let mut msg = IppMessage::new(ops::op::PRINT_JOB);
        let media_size = Attribute::new(
            "media-size",
            tags::BEGIN_COLLECTION,
            vec![Value::Collection(vec![
                Attribute::new("x-dimension", tags::INTEGER, vec![Value::Integer(21000)]),
                Attribute::new("y-dimension", tags::INTEGER, vec![Value::Integer(29700)]),
            ])],
        );
        let media_col = Attribute::new(
            "media-col",
            tags::BEGIN_COLLECTION,
            vec![Value::Collection(vec![
                media_size,
                Attribute::new(
                    "media-type",
                    tags::KEYWORD,
                    vec![Value::Keyword("stationery".into())],
                ),
            ])],
        );
        let mut job = Group::new(tags::JOB);
        job.attributes.push(media_col);
        msg.groups.push(job);

        let bytes = encode(&msg).unwrap();
        let (back, off) = decode(&bytes).unwrap();
        assert_eq!(off, bytes.len());
        assert_eq!(back, msg);
    }

    #[test]
    fn collection_wire_layout() {
        // Verify memberAttrName/endCollection framing byte-for-byte.
        let mut msg = IppMessage::new(ops::op::PRINT_JOB);
        let col = Attribute::new(
            "col",
            tags::BEGIN_COLLECTION,
            vec![Value::Collection(vec![Attribute::new(
                "member",
                tags::INTEGER,
                vec![Value::Integer(1)],
            )])],
        );
        let mut g = Group::new(tags::JOB);
        g.attributes.push(col);
        msg.groups.push(g);

        let bytes = encode(&msg).unwrap();
        // ...job group, begCollection, "col", vallen 0,
        // memberAttrName, namelen 0, vallen 6, "member",
        // integer, namelen 0, vallen 4, 0,0,0,1,
        // endCollection + 4 zeros, END
        let tail = &bytes[bytes.len() - 26..];
        assert_eq!(
            tail,
            &[
                tags::MEMBERNAME,
                0,
                0,
                0,
                6,
                b'm',
                b'e',
                b'm',
                b'b',
                b'e',
                b'r',
                tags::INTEGER,
                0,
                0,
                0,
                4,
                0,
                0,
                0,
                1,
                tags::END_COLLECTION,
                0,
                0,
                0,
                0,
                tags::END,
            ]
        );
    }

    #[test]
    fn multivalue_collection_roundtrip() {
        // 1setOf collections: multiple Collection values on one attribute.
        let mut msg = IppMessage::new(ops::op::PRINT_JOB);
        let attr = Attribute::new(
            "cols",
            tags::BEGIN_COLLECTION,
            vec![
                Value::Collection(vec![Attribute::new(
                    "a",
                    tags::INTEGER,
                    vec![Value::Integer(1)],
                )]),
                Value::Collection(vec![Attribute::new(
                    "b",
                    tags::INTEGER,
                    vec![Value::Integer(2)],
                )]),
            ],
        );
        let mut g = Group::new(tags::JOB);
        g.attributes.push(attr);
        msg.groups.push(g);

        let bytes = encode(&msg).unwrap();
        let (back, _) = decode(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn separator_repeated_group() {
        // Two job-groups on the wire = separator within the job group.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1];
        for _ in 0..2 {
            bytes.push(tags::JOB);
            bytes.extend_from_slice(&[tags::KEYWORD, 0, 4]);
            bytes.extend_from_slice(b"attr");
            bytes.extend_from_slice(&[0, 1]);
            bytes.extend_from_slice(b"x");
        }
        bytes.push(tags::END);

        let (msg, _) = decode(&bytes).unwrap();
        let job = msg.group(tags::JOB).unwrap();
        assert_eq!(job.attributes.len(), 3);
        assert!(job.attributes[1].is_separator());

        // Re-encoding emits the repeated group tag → same bytes.
        assert_eq!(encode(&msg).unwrap(), bytes);
    }

    #[test]
    fn second_operation_group_rejected() {
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::OPERATION];
        bytes.extend_from_slice(&[tags::KEYWORD, 0, 1, b'a', 0, 1, b'x']);
        bytes.push(tags::OPERATION);
        let err = decode(&bytes).unwrap_err();
        assert!(matches!(err, CodecError::InvalidGroupTag { .. }));
    }

    #[test]
    fn zero_tag_rejected() {
        let bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::ZERO, tags::END];
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::InvalidGroupTag { .. })
        ));
    }

    #[test]
    fn out_of_band_values() {
        let mut msg = IppMessage::new(ops::status::OK);
        let mut g = Group::new(tags::JOB);
        g.attributes
            .push(op_attr("unset", tags::NOVALUE, vec![Value::NoValue]));
        g.attributes
            .push(op_attr("del", tags::DELETEATTR, vec![Value::DeleteAttr]));
        msg.groups.push(g);
        let bytes = encode(&msg).unwrap();
        let (back, _) = decode(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn brother_oob_quirk() {
        // A no-value attribute carrying a non-empty payload is remapped
        // to a text value (libcups compat for buggy vendors).
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::NOVALUE, 0, 3]);
        bytes.extend_from_slice(b"oob");
        bytes.extend_from_slice(&[0, 5]);
        bytes.extend_from_slice(b"junk!");
        bytes.push(tags::END);

        let (msg, _) = decode(&bytes).unwrap();
        let attr = msg.group(tags::JOB).unwrap().find("oob").unwrap();
        assert_eq!(attr.tag, tags::TEXT);
        assert_eq!(attr.values, vec![Value::Text("junk!".into())]);
    }

    #[test]
    fn textlike_mixed_setof_coerces() {
        // nameWithLanguage + nameWithoutLanguage in one 1setOf is legal;
        // the attribute adopts the later tag.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::NAMELANG, 0, 4]);
        bytes.extend_from_slice(b"name");
        // value: lang "en" + text "hello"
        bytes.extend_from_slice(&[0, 11, 0, 2, b'e', b'n', 0, 5]);
        bytes.extend_from_slice(b"hello");
        bytes.extend_from_slice(&[tags::NAME, 0, 0, 0, 5]);
        bytes.extend_from_slice(b"world");
        bytes.push(tags::END);

        let (msg, _) = decode(&bytes).unwrap();
        let attr = msg.group(tags::JOB).unwrap().find("name").unwrap();
        assert_eq!(attr.tag, tags::NAME);
        assert_eq!(
            attr.values[0],
            Value::NameWithLanguage {
                lang: "en".into(),
                text: "hello".into()
            }
        );
        assert_eq!(attr.values[1], Value::Name("world".into()));
    }

    #[test]
    fn incompatible_setof_rejected() {
        // integer attr then a uri value → client-error.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::INTEGER, 0, 3]);
        bytes.extend_from_slice(b"num");
        bytes.extend_from_slice(&[0, 4, 0, 0, 0, 5]);
        bytes.extend_from_slice(&[tags::URI, 0, 0, 0, 3]);
        bytes.extend_from_slice(b"uri");
        bytes.push(tags::END);
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::IncompatibleSetOf { .. })
        ));
    }

    #[test]
    fn integer_range_promotion() {
        // integer value then rangeOfInteger value → whole attr becomes range.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::INTEGER, 0, 4]);
        bytes.extend_from_slice(b"nums");
        bytes.extend_from_slice(&[0, 4, 0, 0, 0, 5]);
        bytes.extend_from_slice(&[tags::RANGE, 0, 0, 0, 8, 0, 0, 0, 10, 0, 0, 0, 20]);
        bytes.push(tags::END);

        let (msg, _) = decode(&bytes).unwrap();
        let attr = msg.group(tags::JOB).unwrap().find("nums").unwrap();
        assert_eq!(attr.tag, tags::RANGE);
        assert_eq!(
            attr.values,
            vec![
                Value::Range { low: 5, high: 5 },
                Value::Range { low: 10, high: 20 }
            ]
        );
    }

    #[test]
    fn document_data_offset() {
        // Send-Document: IPP message followed by document bytes.
        let mut msg = IppMessage::new(ops::op::SEND_DOCUMENT);
        let mut g = Group::new(tags::OPERATION);
        g.attributes.push(op_attr(
            "last-document",
            tags::BOOLEAN,
            vec![Value::Boolean(true)],
        ));
        msg.groups.push(g);
        let mut bytes = encode(&msg).unwrap();
        let msg_len = bytes.len();
        bytes.extend_from_slice(b"%PDF-1.7 fake document bytes");

        let (decoded, off) = decode(&bytes).unwrap();
        assert_eq!(off, msg_len);
        assert_eq!(&bytes[off..], b"%PDF-1.7 fake document bytes");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn datetime_resolution_range() {
        let mut msg = IppMessage::new(ops::op::GET_JOBS);
        let mut g = Group::new(tags::JOB);
        g.attributes.push(op_attr(
            "date",
            tags::DATE,
            vec![Value::DateTime([
                0x07, 0xe9, 11, 11, 12, 30, 0, 5, b'+', 1, 0,
            ])],
        ));
        g.attributes.push(op_attr(
            "res",
            tags::RESOLUTION,
            vec![Value::Resolution {
                x: 600,
                y: 600,
                units: 3,
            }],
        ));
        g.attributes.push(op_attr(
            "rng",
            tags::RANGE,
            vec![Value::Range { low: 1, high: 99 }],
        ));
        msg.groups.push(g);
        let bytes = encode(&msg).unwrap();
        let (back, _) = decode(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn named_attr_in_collection_rejected() {
        // memberAttrName with non-empty name field → error.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::BEGIN_COLLECTION, 0, 3]);
        bytes.extend_from_slice(b"col");
        bytes.extend_from_slice(&[0, 0]); // vallen 0
                                          // membername with a non-empty *name* (illegal):
        bytes.extend_from_slice(&[tags::MEMBERNAME, 0, 4]);
        bytes.extend_from_slice(b"oops");
        bytes.extend_from_slice(&[0, 1, b'x']);
        bytes.push(tags::END);
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::MemberNameNotEmpty { .. })
        ));
    }

    #[test]
    fn invalid_attribute_name_rejected() {
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::KEYWORD, 0, 3]);
        bytes.extend_from_slice(b"a b"); // space is invalid
        bytes.extend_from_slice(&[0, 1, b'x']);
        bytes.push(tags::END);
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::InvalidName { .. })
        ));
    }

    #[test]
    fn value_without_attribute_rejected() {
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::KEYWORD, 0, 0, 0, 1, b'x']);
        bytes.push(tags::END);
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::ValueWithoutAttribute { .. })
        ));
    }

    #[test]
    fn truncated_header_rejected() {
        assert!(matches!(
            decode(&[2, 0, 0]),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn fuzz_smoke_no_panics() {
        // Cheap determinism: feed byte permutations; must error, not panic.
        let mut state = 0x1234_5678u64;
        let mut rng = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = usize::try_from(rng() % 64).unwrap_or(0);
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push(u8::try_from(rng() % 256).unwrap_or(0));
            }
            let _ = decode(&buf);
        }
    }

    #[test]
    fn decode_limits_attribute_count_and_separators() {
        let mut msg = IppMessage::new(ops::op::GET_JOBS);
        let mut g = Group::new(tags::JOB);
        for i in 0..5 {
            g.attributes.push(op_attr(
                &format!("a{i}"),
                tags::INTEGER,
                vec![Value::Integer(i)],
            ));
        }
        msg.groups.push(g);
        let bytes = encode(&msg).unwrap();

        let limits = DecodeLimits {
            max_attributes: 4,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            decode_with_limits(&bytes, &limits),
            Err(CodecError::LimitExceeded {
                kind: "attribute count",
                limit: 4,
                ..
            })
        ));
        let ok_limits = DecodeLimits {
            max_attributes: 5,
            ..DecodeLimits::default()
        };
        assert!(decode_with_limits(&bytes, &ok_limits).is_ok());

        // Separators also count toward attribute limit.
        let mut sep_bytes = vec![2, 0, 0, 0x0a, 0, 0, 0, 1, tags::JOB];
        sep_bytes.extend(std::iter::repeat_n(tags::JOB, 6));
        sep_bytes.push(tags::END);
        assert!(matches!(
            decode_with_limits(&sep_bytes, &limits),
            Err(CodecError::LimitExceeded {
                kind: "attribute count",
                ..
            })
        ));
    }

    #[test]
    fn decode_limits_values_groups_strings_bytes_and_depth() {
        // 1setOf value limit.
        let mut msg = IppMessage::new(ops::op::GET_PRINTER_ATTRIBUTES);
        let mut g = Group::new(tags::OPERATION);
        g.attributes.push(op_attr(
            "requested-attributes",
            tags::KEYWORD,
            (0..6)
                .map(|i| Value::Keyword(format!("attr-{i}").into()))
                .collect(),
        ));
        msg.groups.push(g);
        let bytes = encode(&msg).unwrap();
        let vlim = DecodeLimits {
            max_values: 5,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            decode_with_limits(&bytes, &vlim),
            Err(CodecError::LimitExceeded {
                kind: "value count",
                limit: 5,
                ..
            })
        ));

        // String length cap.
        let slim = DecodeLimits {
            max_string_len: 4,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            decode_with_limits(&bytes, &slim),
            Err(CodecError::LengthOverflow { field: "value", .. })
        ));

        // Total decoded string bytes cap.
        let blim = DecodeLimits {
            max_total_value_bytes: 10,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            decode_with_limits(&bytes, &blim),
            Err(CodecError::LimitExceeded {
                kind: "total value bytes",
                limit: 10,
                ..
            })
        ));

        // Group count cap.
        let mut gmsg = IppMessage::new(ops::op::GET_PRINTER_ATTRIBUTES);
        gmsg.groups.push(Group::new(tags::OPERATION));
        gmsg.groups[0]
            .attributes
            .push(op_attr("a", tags::INTEGER, vec![Value::Integer(1)]));
        gmsg.groups.push(Group::new(tags::JOB));
        gmsg.groups[1]
            .attributes
            .push(op_attr("b", tags::INTEGER, vec![Value::Integer(2)]));
        gmsg.groups.push(Group::new(tags::PRINTER));
        gmsg.groups[2]
            .attributes
            .push(op_attr("c", tags::INTEGER, vec![Value::Integer(3)]));
        let gbytes = encode(&gmsg).unwrap();
        let glim = DecodeLimits {
            max_groups: 2,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            decode_with_limits(&gbytes, &glim),
            Err(CodecError::LimitExceeded {
                kind: "group count",
                limit: 2,
                ..
            })
        ));

        // Strict preset sanity.
        let strict = DecodeLimits::strict();
        assert!(strict.max_attributes < MAX_ATTRIBUTES);
        assert!(strict.max_values < MAX_VALUES);
        assert!(strict.max_string_len < MAX_STRING_LEN);
        assert!(decode_with_limits(&gbytes, &strict).is_ok());
    }

    #[test]
    fn decode_collection_depth_and_member_limits() {
        // Build nested collections deeper than limit.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::BEGIN_COLLECTION, 0, 1, b'c', 0, 0]);
        for _ in 0..11 {
            bytes.extend_from_slice(&[tags::MEMBERNAME, 0, 0, 0, 1, b'm']);
            bytes.extend_from_slice(&[tags::BEGIN_COLLECTION, 0, 0, 0, 0]);
        }
        bytes.push(tags::END);
        assert!(matches!(decode(&bytes), Err(CodecError::CollectionTooDeep)));

        // Collection member counts against max_attributes.
        let mut cbytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        cbytes.extend_from_slice(&[tags::BEGIN_COLLECTION, 0, 1, b'c', 0, 0]);
        cbytes.extend_from_slice(&[
            tags::MEMBERNAME,
            0,
            0,
            0,
            1,
            b'a',
            tags::INTEGER,
            0,
            0,
            0,
            4,
            0,
            0,
            0,
            1,
        ]);
        cbytes.extend_from_slice(&[
            tags::MEMBERNAME,
            0,
            0,
            0,
            1,
            b'b',
            tags::INTEGER,
            0,
            0,
            0,
            4,
            0,
            0,
            0,
            2,
        ]);
        cbytes.extend_from_slice(&[tags::END_COLLECTION, 0, 0, 0, 0, tags::END]);
        let lim = DecodeLimits {
            max_attributes: 2,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            decode_with_limits(&cbytes, &lim),
            Err(CodecError::LimitExceeded {
                kind: "attribute count",
                ..
            })
        ));
    }

    #[test]
    fn all_value_types_and_model_helpers() {
        let mut msg = IppMessage::new(ops::status::OK);
        msg.push(
            tags::OPERATION,
            op_attr(
                "charset",
                tags::CHARSET,
                vec![Value::Charset("utf-8".into())],
            ),
        );
        msg.operation_group().attributes.push(op_attr(
            "lang",
            tags::LANGUAGE,
            vec![Value::NaturalLanguage("en".into())],
        ));
        let g = msg.new_group_mut(tags::JOB);
        g.attributes.extend([
            op_attr("u", tags::UNSUPPORTED, vec![Value::Unsupported]),
            op_attr("d", tags::DEFAULT, vec![Value::Default]),
            op_attr("k", tags::UNKNOWN, vec![Value::Unknown]),
            op_attr("ns", tags::NOTSETTABLE, vec![Value::NotSettable]),
            op_attr("ad", tags::ADMINDEFINE, vec![Value::AdminDefine]),
            op_attr("en", tags::ENUM, vec![Value::Enum(4)]),
            op_attr("bl", tags::BOOLEAN, vec![Value::Boolean(false)]),
            op_attr("os", tags::STRING, vec![Value::OctetString(vec![1, 2, 3])]),
            op_attr(
                "rs",
                tags::RESERVED_STRING,
                vec![Value::ReservedString(vec![4, 5])],
            ),
            op_attr("txt", tags::TEXT, vec![Value::Text("hello".into())]),
            op_attr("nm", tags::NAME, vec![Value::Name("alice".into())]),
            op_attr("us", tags::URISCHEME, vec![Value::UriScheme("ipp".into())]),
            op_attr(
                "mm",
                tags::MIMETYPE,
                vec![Value::MimeMediaType("application/pdf".into())],
            ),
            op_attr(
                "tl",
                tags::TEXTLANG,
                vec![Value::TextWithLanguage {
                    lang: "en".into(),
                    text: "hi".into(),
                }],
            ),
            op_attr(
                "nl",
                tags::NAMELANG,
                vec![Value::NameWithLanguage {
                    lang: "en".into(),
                    text: "bob".into(),
                }],
            ),
            op_attr(
                "ext",
                tags::EXTENSION,
                vec![Value::UnknownValue {
                    tag: tags::EXTENSION,
                    data: vec![9, 8],
                }],
            ),
        ]);

        let bytes = encode(&msg).unwrap();
        let (back, off) = decode(&bytes).unwrap();
        assert_eq!(off, bytes.len());
        assert_eq!(back, msg);

        // Model helpers.
        assert_eq!(back.find_all("nm").count(), 1);
        let nm = back.find(tags::JOB, "nm").unwrap();
        assert_eq!(nm.text().as_deref(), Some("alice"));
        assert_eq!(nm.int(), None);
        assert_eq!(back.find(tags::JOB, "en").unwrap().int(), Some(4));
        assert_eq!(back.find(tags::JOB, "bl").unwrap().int(), Some(0));
        assert_eq!(
            back.find(tags::JOB, "tl").unwrap().text().as_deref(),
            Some("hi")
        );
        assert_eq!(back.find(tags::JOB, "os").unwrap().text(), None);
    }

    #[test]
    fn text_helpers_and_value_tags() {
        let t = Text::from(String::from("abc"));
        assert_eq!(t.as_bytes(), b"abc");
        assert_eq!(t.as_ref(), b"abc");
        assert!(!t.is_empty());
        assert_eq!(format!("{t}"), "abc");
        assert_eq!(t, "abc");
        assert_eq!(t, *"abc");
        assert!(Text::new().is_empty());
        assert_eq!(Text::from(vec![b'x']).as_bytes(), b"x");

        // Value::tag coverage for every variant including MemberName.
        assert_eq!(Value::MemberName("m".into()).tag(), tags::MEMBERNAME);
        assert_eq!(Value::NoValue.tag(), tags::NOVALUE);
        assert_eq!(Value::DeleteAttr.tag(), tags::DELETEATTR);
        assert_eq!(Value::Integer(1).tag(), tags::INTEGER);
        assert_eq!(Value::DateTime([0; 11]).tag(), tags::DATE);
        assert_eq!(
            Value::Resolution {
                x: 1,
                y: 1,
                units: 3
            }
            .tag(),
            tags::RESOLUTION
        );
        assert_eq!(Value::Range { low: 1, high: 2 }.tag(), tags::RANGE);
        assert_eq!(Value::Collection(vec![]).tag(), tags::BEGIN_COLLECTION);
        assert_eq!(Value::Keyword("k".into()).tag(), tags::KEYWORD);
        assert_eq!(Value::Uri("u".into()).tag(), tags::URI);

        // Encode MemberName directly as an attribute value to verify encode arm.
        let mut m2 = IppMessage::new(ops::status::OK);
        m2.push(
            tags::JOB,
            op_attr("mn", tags::MEMBERNAME, vec![Value::MemberName("x".into())]),
        );
        assert!(encode(&m2).is_ok());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // table of malformed IPP byte vectors
    fn decoder_error_paths_and_display() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            // LengthOverflow on name (>32767).
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::KEYWORD,
                    0x80,
                    0x01,
                ],
                "name length",
            ),
            // LengthOverflow on value (>32767).
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::KEYWORD,
                    0,
                    1,
                    b'a',
                    0x80,
                    0x01,
                ],
                "value length",
            ),
            // Top-level END_COLLECTION with non-empty value.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::END_COLLECTION,
                    0,
                    0,
                    0,
                    1,
                    0,
                ],
                "non-empty value",
            ),
            // Top-level MEMBERNAME with non-empty name.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::MEMBERNAME,
                    0,
                    1,
                    b'a',
                ],
                "non-empty name",
            ),
            // Top-level MEMBERNAME outside collection.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::MEMBERNAME,
                    0,
                    0,
                    0,
                    1,
                    b'a',
                ],
                "outside of collection",
            ),
            // Bad integer length.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::INTEGER,
                    0,
                    1,
                    b'a',
                    0,
                    2,
                    0,
                    1,
                    tags::END,
                ],
                "bad value length",
            ),
            // Bad boolean length.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BOOLEAN,
                    0,
                    1,
                    b'a',
                    0,
                    2,
                    0,
                    1,
                    tags::END,
                ],
                "bad value length",
            ),
            // Bad date length.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::DATE,
                    0,
                    1,
                    b'a',
                    0,
                    2,
                    0,
                    1,
                    tags::END,
                ],
                "bad value length",
            ),
            // Bad resolution length.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::RESOLUTION,
                    0,
                    1,
                    b'a',
                    0,
                    2,
                    0,
                    1,
                    tags::END,
                ],
                "bad value length",
            ),
            // Bad range length.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::RANGE,
                    0,
                    1,
                    b'a',
                    0,
                    2,
                    0,
                    1,
                    tags::END,
                ],
                "bad value length",
            ),
            // Bad begCollection length.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'a',
                    0,
                    1,
                    0,
                    tags::END,
                ],
                "bad value length",
            ),
            // Bad textWithLanguage lengths (<2, short lang, short text).
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::TEXTLANG,
                    0,
                    1,
                    b'a',
                    0,
                    1,
                    0,
                    tags::END,
                ],
                "bad value length",
            ),
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::TEXTLANG,
                    0,
                    1,
                    b'a',
                    0,
                    3,
                    0,
                    5,
                    0,
                    tags::END,
                ],
                "bad value length",
            ),
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::TEXTLANG,
                    0,
                    1,
                    b'a',
                    0,
                    5,
                    0,
                    1,
                    b'e',
                    0,
                    9,
                    tags::END,
                ],
                "bad value length",
            ),
            // Group tag inside collection.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'c',
                    0,
                    0,
                    tags::JOB,
                ],
                "inside collection",
            ),
            // ZERO / OPERATION inside collection.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'c',
                    0,
                    0,
                    tags::OPERATION,
                ],
                "invalid group tag",
            ),
            // END_COLLECTION with named attr or non-empty value inside collection.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'c',
                    0,
                    0,
                    tags::END_COLLECTION,
                    0,
                    1,
                ],
                "named attribute inside collection",
            ),
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'c',
                    0,
                    0,
                    tags::END_COLLECTION,
                    0,
                    0,
                    0,
                    1,
                ],
                "non-empty value",
            ),
            // MEMBERNAME empty value / overflow / invalid name inside collection.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'c',
                    0,
                    0,
                    tags::MEMBERNAME,
                    0,
                    0,
                    0,
                    0,
                ],
                "empty value",
            ),
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'c',
                    0,
                    0,
                    tags::MEMBERNAME,
                    0,
                    0,
                    0x80,
                    0x01,
                ],
                "name length",
            ),
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'c',
                    0,
                    0,
                    tags::MEMBERNAME,
                    0,
                    0,
                    0,
                    2,
                    b' ',
                    b'!',
                ],
                "invalid attribute/member name",
            ),
            // Named value inside collection.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'c',
                    0,
                    0,
                    tags::INTEGER,
                    0,
                    1,
                ],
                "named attribute inside collection",
            ),
            // Value without member inside collection.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BEGIN_COLLECTION,
                    0,
                    1,
                    b'c',
                    0,
                    0,
                    tags::INTEGER,
                    0,
                    0,
                    0,
                    4,
                    0,
                    0,
                    0,
                    1,
                ],
                "without a name",
            ),
            // Incompatible 1setOf: textlike + int, boolean + int.
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::TEXT,
                    0,
                    1,
                    b'a',
                    0,
                    1,
                    b'x',
                    tags::INTEGER,
                    0,
                    0,
                    0,
                    4,
                    0,
                    0,
                    0,
                    1,
                ],
                "1setOf tag mismatch",
            ),
            (
                vec![
                    2,
                    0,
                    0,
                    0x0b,
                    0,
                    0,
                    0,
                    1,
                    tags::JOB,
                    tags::BOOLEAN,
                    0,
                    1,
                    b'a',
                    0,
                    1,
                    1,
                    tags::INTEGER,
                    0,
                    0,
                    0,
                    4,
                    0,
                    0,
                    0,
                    1,
                ],
                "1setOf tag mismatch",
            ),
        ];
        for (pkt, expected) in cases {
            let err = decode(&pkt).expect_err("must fail");
            assert!(
                err.to_string().contains(expected),
                "expected '{expected}' in '{err}'"
            );
        }

        // Top-level END_COLLECTION with zero length cleanly ends message.
        let top_end = vec![
            2,
            0,
            0,
            0x0b,
            0,
            0,
            0,
            1,
            tags::JOB,
            tags::END_COLLECTION,
            0,
            0,
            0,
            0,
        ];
        assert!(decode(&top_end).is_ok());

        // END tag inside collection terminates entire message leniently.
        let col_end = vec![
            2,
            0,
            0,
            0x0b,
            0,
            0,
            0,
            1,
            tags::JOB,
            tags::BEGIN_COLLECTION,
            0,
            1,
            b'c',
            0,
            0,
            tags::END,
        ];
        assert!(decode(&col_end).is_ok());

        // Range followed by integer widens integer to range.
        let rng_int = vec![
            2,
            0,
            0,
            0x0b,
            0,
            0,
            0,
            1,
            tags::JOB,
            tags::RANGE,
            0,
            1,
            b'r',
            0,
            8,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            5,
            tags::INTEGER,
            0,
            0,
            0,
            4,
            0,
            0,
            0,
            9,
            tags::END,
        ];
        let (m, _) = decode(&rng_int).unwrap();
        assert_eq!(
            m.find(tags::JOB, "r").unwrap().values,
            vec![
                Value::Range { low: 1, high: 5 },
                Value::Range { low: 9, high: 9 }
            ]
        );

        // Encode errors for oversized name/value/lang/text.
        let mut big = IppMessage::new(ops::status::OK);
        big.push(
            tags::JOB,
            Attribute::new(
                Text(vec![b'a'; MAX_NAME_LEN + 1]),
                tags::KEYWORD,
                vec![Value::Keyword("x".into())],
            ),
        );
        assert!(encode(&big)
            .unwrap_err()
            .to_string()
            .contains("encode error"));

        let mut bigv = IppMessage::new(ops::status::OK);
        bigv.push(
            tags::JOB,
            op_attr(
                "x",
                tags::TEXT,
                vec![Value::Text(Text(vec![b'a'; MAX_VALUE_LEN + 1]))],
            ),
        );
        assert!(encode(&bigv).is_err());

        // Display checks on remaining error variants.
        assert!(CodecError::Truncated { needed: 2, at: 0 }
            .to_string()
            .contains("truncated"));
        assert!(CodecError::CollectionTooDeep
            .to_string()
            .contains("10 deep"));
        assert!(CodecError::LimitExceeded {
            kind: "test",
            limit: 1,
            at: 2
        }
        .to_string()
        .contains("test limit (1)"));
    }

    #[test]
    fn tags_ops_and_status_tables_complete() {
        // Exercise every known tag name + unknown tag.
        for tag in 0u8..=0xff {
            let n = tags::name(tag);
            assert_ne!(n, "");
        }
        assert!(tags::is_group_tag(tags::OPERATION));
        assert!(!tags::is_group_tag(tags::ZERO));
        assert!(tags::is_out_of_band(tags::UNSUPPORTED));
        assert!(tags::is_out_of_band(tags::ADMINDEFINE));
        assert!(!tags::is_out_of_band(tags::INTEGER));
        assert!(tags::is_textlike(tags::TEXTLANG));
        assert!(tags::is_textlike(tags::MIMETYPE));
        assert!(!tags::is_textlike(tags::INTEGER));

        // Exercise every op name and reverse lookup.
        for code in (0x0002u16..=0x0064).chain(0x4000..=0x4028).chain([0x9999]) {
            let name = ops::op::name(code);
            assert_ne!(name, "");
            if !name.starts_with('(') {
                assert_eq!(ops::op::value(name), Some(code), "mismatch for {name}");
            }
        }
        assert_eq!(ops::op::value("0x4001"), Some(ops::op::CUPS_GET_DEFAULT));
        assert_eq!(ops::op::value("windows-ext"), Some(ops::op::PRIVATE));
        assert_eq!(
            ops::op::value("Create-Job-Subscription"),
            Some(ops::op::CREATE_JOB_SUBSCRIPTIONS)
        );
        assert_eq!(ops::op::value("No-Such-Op"), None);

        // Exercise every status name.
        for code in (0x0000u16..=0x0007)
            .chain([0x0200, 0x0280])
            .chain(0x0400..=0x0420)
            .chain(0x049c..=0x049f)
            .chain(0x0500..=0x050c)
            .chain(0x1000..=0x1003)
            .chain([0xffff])
        {
            assert_ne!(ops::status::name(code), "");
        }
    }
}
