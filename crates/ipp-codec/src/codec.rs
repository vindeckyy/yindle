//! IPP wire encoding/decoding.
//!
//! The decoder mirrors `ipp_read_io()` in libcups: delimiter-group and
//! separator handling, `memberAttrName`/`endCollection` framing, the
//! out-of-band-with-payload → text quirk for non-conforming vendors,
//! `1setOf` value-tag coercion (text-like mixing, integer→range
//! promotion), the 10-level collection depth limit, and the RFC 8011
//! keyword check on attribute/member names.
//!
//! The encoder mirrors `ippWriteIO()`: first value carries the name,
//! subsequent values use a zero-length name, separators re-emit the
//! group delimiter byte, collections serialize as `memberAttrName` +
//! value-tag pairs terminated by `endCollection`, and the message ends
//! with the single `end-of-attributes` byte `0x03`.

use crate::error::CodecError;
use crate::model::{Attribute, Group, IppMessage, Text, Value};
use crate::tags;

/// Maximum wire length for names and values (`IPP_BUF_SIZE - 1`).
pub const MAX_NAME_LEN: usize = 32767;
pub const MAX_VALUE_LEN: usize = 32767;
/// Maximum collection nesting depth, matching `ipp_read_io`.
pub const MAX_COLLECTION_DEPTH: usize = 10;
/// Default hard cap on delimiter groups in a single decoded message.
pub const MAX_GROUPS: usize = 4096;
/// Default hard cap on total attributes (including separators and collection members).
pub const MAX_ATTRIBUTES: usize = 16_384;
/// Default hard cap on total values across all attributes in a single message.
pub const MAX_VALUES: usize = 65_536;
/// Default hard cap on individual decoded string/octet-string lengths.
pub const MAX_STRING_LEN: usize = MAX_VALUE_LEN;
/// Default hard cap on cumulative decoded string/byte value payload (8 MiB).
pub const MAX_TOTAL_VALUE_BYTES: usize = 8 * 1024 * 1024;

/// Safety limits applied while decoding an IPP message to bound CPU and memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum number of attribute groups.
    pub max_groups: usize,
    /// Maximum total attributes (including group separators and collection members).
    pub max_attributes: usize,
    /// Maximum total values across all attributes.
    pub max_values: usize,
    /// Maximum length of any single string/octet-string value (clamped to [`MAX_VALUE_LEN`]).
    pub max_string_len: usize,
    /// Maximum cumulative bytes across all decoded string/octet-string values.
    pub max_total_value_bytes: usize,
    /// Maximum collection nesting depth.
    pub max_collection_depth: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_groups: MAX_GROUPS,
            max_attributes: MAX_ATTRIBUTES,
            max_values: MAX_VALUES,
            max_string_len: MAX_STRING_LEN,
            max_total_value_bytes: MAX_TOTAL_VALUE_BYTES,
            max_collection_depth: MAX_COLLECTION_DEPTH,
        }
    }
}

impl DecodeLimits {
    /// Tighter limits intended for untrusted incoming client IPP requests.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            max_groups: 64,
            max_attributes: 4096,
            max_values: 16_384,
            max_string_len: 4096,
            max_total_value_bytes: 2 * 1024 * 1024,
            max_collection_depth: MAX_COLLECTION_DEPTH,
        }
    }
}

/// Decode `buf` into an [`IppMessage`] using [`DecodeLimits::default()`],
/// returning the message and the offset where document data
/// (`Print-Job`/`Send-Document` payload) begins — i.e., the first byte after
/// `end-of-attributes`.
///
/// # Errors
/// See [`CodecError`] for the full failure taxonomy; it deliberately
/// mirrors the malformed-input cases libcups rejects, plus safety caps.
pub fn decode(buf: &[u8]) -> Result<(IppMessage, usize), CodecError> {
    decode_with_limits(buf, &DecodeLimits::default())
}

/// Decode `buf` into an [`IppMessage`] enforcing custom [`DecodeLimits`].
///
/// # Errors
/// Returns [`CodecError::LimitExceeded`] or [`CodecError::LengthOverflow`]
/// when the input violates any configured cap, or a protocol error on malformed input.
pub fn decode_with_limits(
    buf: &[u8],
    limits: &DecodeLimits,
) -> Result<(IppMessage, usize), CodecError> {
    let mut d = Decoder {
        buf,
        pos: 0,
        major: 0,
        minor: 0,
        code: 0,
        request_id: 0,
        msg_done: false,
        limits: *limits,
        group_count: 0,
        attr_count: 0,
        value_count: 0,
        total_value_bytes: 0,
    };
    d.header()?;
    let groups = d.groups(0)?;
    Ok((
        IppMessage {
            version: (d.major, d.minor),
            code: d.code,
            request_id: d.request_id,
            groups,
            document: Vec::new(),
        },
        d.pos,
    ))
}

/// Encode `msg` into its wire form (header + attributes + `0x03`), then
/// append `msg.document` — the payload `Get-Document`/`Send-Document`
/// carry after the attribute groups.
pub fn encode(msg: &IppMessage) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(512);
    out.push(msg.version.0);
    out.push(msg.version.1);
    out.extend_from_slice(&msg.code.to_be_bytes());
    out.extend_from_slice(&msg.request_id.to_be_bytes());
    for group in &msg.groups {
        encode_group(group, &mut out)?;
    }
    out.push(tags::END);
    out.extend_from_slice(&msg.document);
    Ok(out)
}

fn encode_group(group: &Group, out: &mut Vec<u8>) -> Result<(), CodecError> {
    let mut started = false;
    for attr in &group.attributes {
        if attr.is_separator() {
            out.push(group.tag);
            continue;
        }
        if !started {
            out.push(group.tag);
            started = true;
        }
        encode_attribute(attr, out)?;
    }
    Ok(())
}

fn encode_attribute(attr: &Attribute, out: &mut Vec<u8>) -> Result<(), CodecError> {
    for (i, value) in attr.values.iter().enumerate() {
        // First value carries the attribute name; the rest are appended
        // with a zero-length name (RFC 8010 §3.1.5).
        let wire_tag = if i == 0 { attr.tag } else { value.tag() };
        out.push(wire_tag);
        if i == 0 {
            push_u16_name(&attr.name, out)?;
        } else {
            out.extend_from_slice(&[0, 0]);
        }
        encode_value(value, out)?;
    }
    Ok(())
}

fn encode_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CodecError> {
    match value {
        Value::Unsupported
        | Value::Default
        | Value::Unknown
        | Value::NoValue
        | Value::NotSettable
        | Value::DeleteAttr
        | Value::AdminDefine => out.extend_from_slice(&[0, 0]),
        Value::Integer(v) | Value::Enum(v) => {
            out.extend_from_slice(&[0, 4]);
            out.extend_from_slice(&v.to_be_bytes());
        }
        Value::Boolean(b) => {
            out.extend_from_slice(&[0, 1]);
            out.push(u8::from(*b));
        }
        Value::OctetString(bytes) | Value::ReservedString(bytes) => {
            push_u16_data(bytes, out)?;
        }
        Value::DateTime(dt) => {
            out.extend_from_slice(&[0, 11]);
            out.extend_from_slice(dt);
        }
        Value::Resolution { x, y, units } => {
            out.extend_from_slice(&[0, 9]);
            out.extend_from_slice(&x.to_be_bytes());
            out.extend_from_slice(&y.to_be_bytes());
            out.push(*units);
        }
        Value::Range { low, high } => {
            out.extend_from_slice(&[0, 8]);
            out.extend_from_slice(&low.to_be_bytes());
            out.extend_from_slice(&high.to_be_bytes());
        }
        Value::Collection(members) => {
            out.extend_from_slice(&[0, 0]);
            encode_members(members, out)?;
        }
        Value::TextWithLanguage { lang, text } | Value::NameWithLanguage { lang, text } => {
            let mut data = Vec::with_capacity(lang.0.len() + text.0.len() + 4);
            data.extend_from_slice(
                &u16::try_from(lang.0.len())
                    .map_err(|_| CodecError::Encode("language too long".into()))?
                    .to_be_bytes(),
            );
            data.extend_from_slice(&lang.0);
            data.extend_from_slice(
                &u16::try_from(text.0.len())
                    .map_err(|_| CodecError::Encode("text too long".into()))?
                    .to_be_bytes(),
            );
            data.extend_from_slice(&text.0);
            push_u16_data(&data, out)?;
        }
        Value::Text(t)
        | Value::Name(t)
        | Value::Keyword(t)
        | Value::Uri(t)
        | Value::UriScheme(t)
        | Value::Charset(t)
        | Value::NaturalLanguage(t)
        | Value::MimeMediaType(t)
        | Value::MemberName(t) => push_u16_data(&t.0, out)?,
        Value::UnknownValue { data, .. } => push_u16_data(data, out)?,
    }
    Ok(())
}

fn encode_members(members: &[Attribute], out: &mut Vec<u8>) -> Result<(), CodecError> {
    for member in members {
        // memberAttrName: tag, empty name, value = member name.
        out.push(tags::MEMBERNAME);
        out.extend_from_slice(&[0, 0]);
        push_u16_data(&member.name.0, out)?;
        for value in &member.values {
            out.push(value.tag());
            out.extend_from_slice(&[0, 0]);
            encode_value(value, out)?;
        }
    }
    out.push(tags::END_COLLECTION);
    out.extend_from_slice(&[0, 0, 0, 0]);
    Ok(())
}

fn push_u16_name(name: &Text, out: &mut Vec<u8>) -> Result<(), CodecError> {
    if name.0.len() > MAX_NAME_LEN {
        return Err(CodecError::Encode(format!(
            "attribute name too long: {}",
            name.0.len()
        )));
    }
    let len =
        u16::try_from(name.0.len()).map_err(|_| CodecError::Encode("name too long".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&name.0);
    Ok(())
}

fn push_u16_data(data: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
    if data.len() > MAX_VALUE_LEN {
        return Err(CodecError::Encode(format!(
            "value too long: {}",
            data.len()
        )));
    }
    let len = u16::try_from(data.len())
        .map_err(|_| CodecError::Encode(format!("value too long: {}", data.len())))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    // decoded header fields
    major: u8,
    minor: u8,
    code: u16,
    request_id: i32,
    /// Set when a collection member parse hit `end-of-attributes`;
    /// ends the whole message (see `members()`).
    msg_done: bool,
    limits: DecodeLimits,
    group_count: usize,
    attr_count: usize,
    value_count: usize,
    total_value_bytes: usize,
}

enum CollectionEnd {
    /// `endCollection` closed the collection.
    EndCollection,
    /// The message-level `end-of-attributes`/`endCollection` tag arrived
    /// — treat the entire message as finished (libcups is lenient here).
    EndOfMessage,
}

impl<'a> Decoder<'a> {
    fn count_group(&mut self, at: usize) -> Result<(), CodecError> {
        if self.group_count >= self.limits.max_groups {
            return Err(CodecError::LimitExceeded {
                kind: "group count",
                limit: self.limits.max_groups,
                at,
            });
        }
        self.group_count += 1;
        Ok(())
    }

    fn count_attr(&mut self, at: usize) -> Result<(), CodecError> {
        if self.attr_count >= self.limits.max_attributes {
            return Err(CodecError::LimitExceeded {
                kind: "attribute count",
                limit: self.limits.max_attributes,
                at,
            });
        }
        self.attr_count += 1;
        Ok(())
    }

    fn count_value(&mut self, at: usize) -> Result<(), CodecError> {
        if self.value_count >= self.limits.max_values {
            return Err(CodecError::LimitExceeded {
                kind: "value count",
                limit: self.limits.max_values,
                at,
            });
        }
        self.value_count += 1;
        Ok(())
    }

    fn account_string(&mut self, len: usize, at: usize) -> Result<(), CodecError> {
        let cap = self.limits.max_string_len.min(MAX_VALUE_LEN);
        if len > cap {
            return Err(CodecError::LengthOverflow {
                field: "value",
                len,
                at,
            });
        }
        let next = self
            .total_value_bytes
            .checked_add(len)
            .filter(|&sum| sum <= self.limits.max_total_value_bytes)
            .ok_or(CodecError::LimitExceeded {
                kind: "total value bytes",
                limit: self.limits.max_total_value_bytes,
                at,
            })?;
        self.total_value_bytes = next;
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| CodecError::truncated(1, self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn i32(&mut self) -> Result<i32, CodecError> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.buf.len() - self.pos < n {
            return Err(CodecError::truncated(n, self.pos));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn header(&mut self) -> Result<(), CodecError> {
        let h = self.take(8)?;
        self.major = h[0];
        self.minor = h[1];
        self.code = u16::from_be_bytes([h[2], h[3]]);
        self.request_id = i32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        Ok(())
    }

    /// Read attribute groups until `end-of-attributes`.
    fn groups(&mut self, depth: usize) -> Result<Vec<Group>, CodecError> {
        let mut groups: Vec<Group> = Vec::new();
        let mut curtag = tags::ZERO;
        let mut current: Option<usize> = None; // index into current group's attrs
        let mut done = false;

        while !done {
            let at = self.pos;
            let tag = self.u8()?;

            if tag == tags::END {
                done = true;
                continue;
            }
            if tag == tags::ZERO || (tag == tags::OPERATION && curtag != tags::ZERO) {
                return Err(CodecError::InvalidGroupTag { tag, at });
            }
            if tags::is_group_tag(tag) {
                if curtag == tag {
                    // Repeated delimiter for the same group → separator.
                    self.count_attr(at)?;
                    groups
                        .last_mut()
                        .expect("curtag set implies a group exists")
                        .attributes
                        .push(Attribute::separator());
                } else {
                    self.count_group(at)?;
                    groups.push(Group::new(tag));
                    curtag = tag;
                }
                current = None;
                continue;
            }

            // A value-tag entry: [tag][namelen:u16][name][vallen:u16][value]
            let namelen = usize::from(self.u16()?);
            if namelen > MAX_NAME_LEN {
                return Err(CodecError::LengthOverflow {
                    field: "name",
                    len: namelen,
                    at,
                });
            }

            if tag == tags::MEMBERNAME || tag == tags::END_COLLECTION {
                // Neither is legal at message level.
                if tag == tags::END_COLLECTION {
                    // Mirrors ipp_read_io: an endCollection at top level
                    // must have a zero value and ends the message.
                    let vlen = usize::from(self.u16()?);
                    if vlen > 0 {
                        return Err(CodecError::CollectionValueNotEmpty { at });
                    }
                    done = true;
                    continue;
                }
                if namelen != 0 {
                    return Err(CodecError::MemberNameNotEmpty { at });
                }
                return Err(CodecError::MemberNameOutsideCollection { at });
            }

            if namelen == 0 {
                // Additional value for the current attribute.
                let idx = current.ok_or(CodecError::ValueWithoutAttribute { at })?;
                let group = groups
                    .last_mut()
                    .ok_or(CodecError::ValueWithoutAttribute { at })?;
                let attr = &mut group.attributes[idx];
                self.read_and_append(attr, tag, at, depth)?;
            } else {
                // New named attribute.
                let name = self.take(namelen)?;
                if !is_valid_keyword(name) {
                    return Err(CodecError::InvalidName { at });
                }
                self.count_attr(at)?;
                let group = groups
                    .last_mut()
                    .ok_or(CodecError::ValueWithoutAttribute { at })?;
                group
                    .attributes
                    .push(Attribute::new(Text(name.to_vec()), tag, Vec::new()));
                let idx = group.attributes.len() - 1;
                current = Some(idx);
                let attr = &mut group.attributes[idx];
                self.read_and_append(attr, tag, at, depth)?;
            }
            if self.msg_done {
                done = true;
            }
        }

        Ok(groups)
    }

    /// Read value length + value, apply `1setOf` coercion rules, and
    /// append to `attr`. For `begCollection` this recurses into member
    /// parsing.
    fn read_and_append(
        &mut self,
        attr: &mut Attribute,
        tag: u8,
        at: usize,
        depth: usize,
    ) -> Result<(), CodecError> {
        // Coercion rules on continuation values, mirroring ipp_read_io.
        if attr.tag != tag && !attr.values.is_empty() {
            if tags::is_textlike(attr.tag) {
                if !tags::is_textlike(tag) && tag != tags::NOVALUE {
                    return Err(CodecError::IncompatibleSetOf {
                        attr_tag: attr.tag,
                        tag,
                        at,
                    });
                }
                attr.tag = tag;
            } else if attr.tag == tags::INTEGER || attr.tag == tags::RANGE {
                if tag != tags::INTEGER && tag != tags::RANGE {
                    return Err(CodecError::IncompatibleSetOf {
                        attr_tag: attr.tag,
                        tag,
                        at,
                    });
                }
                if attr.tag == tags::INTEGER && tag == tags::RANGE {
                    // ippSetValueTag(RANGE): widen stored ints to ranges.
                    for v in &mut attr.values {
                        if let Value::Integer(n) = *v {
                            *v = Value::Range { low: n, high: n };
                        }
                    }
                    attr.tag = tags::RANGE;
                }
            } else {
                return Err(CodecError::IncompatibleSetOf {
                    attr_tag: attr.tag,
                    tag,
                    at,
                });
            }
        }

        // A pending collection member adopts the incoming value tag.
        if attr.tag == tags::ZERO {
            attr.tag = tag;
        }

        self.count_value(at)?;
        let value = self.value(attr, tag, at, depth)?;
        attr.values.push(value);
        Ok(())
    }

    /// Read `vallen` + value bytes for `tag`, decode to a [`Value`].
    #[allow(clippy::too_many_lines)]
    fn value(
        &mut self,
        attr: &mut Attribute,
        tag: u8,
        at: usize,
        depth: usize,
    ) -> Result<Value, CodecError> {
        let n = usize::from(self.u16()?);
        if n > MAX_VALUE_LEN {
            return Err(CodecError::LengthOverflow {
                field: "value",
                len: n,
                at,
            });
        }

        match tag {
            tags::INTEGER | tags::ENUM => {
                if n != 4 {
                    return Err(CodecError::BadValueLength {
                        tag,
                        expected: 4,
                        got: n,
                        at,
                    });
                }
                let v = i32::from_be_bytes(self.take(4)?.try_into().unwrap());
                // Range attribute being fed an integer → {n, n}.
                if attr.tag == tags::RANGE {
                    Ok(Value::Range { low: v, high: v })
                } else if tag == tags::INTEGER {
                    Ok(Value::Integer(v))
                } else {
                    Ok(Value::Enum(v))
                }
            }
            tags::BOOLEAN => {
                if n != 1 {
                    return Err(CodecError::BadValueLength {
                        tag,
                        expected: 1,
                        got: n,
                        at,
                    });
                }
                Ok(Value::Boolean(self.u8()? != 0))
            }
            t if tags::is_out_of_band(t) => {
                // Zero-length is proper; non-empty payloads get remapped
                // to text (libcups' workaround for non-conforming vendors).
                if attr.tag == t && n == 0 {
                    Ok(out_of_band_value(t))
                } else {
                    self.account_string(n, at)?;
                    if attr.tag == t {
                        attr.tag = tags::TEXT;
                    }
                    Ok(Value::Text(Text(self.take(n)?.to_vec())))
                }
            }
            tags::STRING => {
                self.account_string(n, at)?;
                Ok(Value::OctetString(self.take(n)?.to_vec()))
            }
            tags::DATE => {
                if n != 11 {
                    return Err(CodecError::BadValueLength {
                        tag,
                        expected: 11,
                        got: n,
                        at,
                    });
                }
                let mut dt = [0u8; 11];
                dt.copy_from_slice(self.take(11)?);
                Ok(Value::DateTime(dt))
            }
            tags::RESOLUTION => {
                if n != 9 {
                    return Err(CodecError::BadValueLength {
                        tag,
                        expected: 9,
                        got: n,
                        at,
                    });
                }
                let x = self.i32()?;
                let y = self.i32()?;
                let units = self.u8()?;
                Ok(Value::Resolution { x, y, units })
            }
            tags::RANGE => {
                if n != 8 {
                    return Err(CodecError::BadValueLength {
                        tag,
                        expected: 8,
                        got: n,
                        at,
                    });
                }
                let low = self.i32()?;
                let high = self.i32()?;
                Ok(Value::Range { low, high })
            }
            tags::BEGIN_COLLECTION => {
                if n != 0 {
                    return Err(CodecError::BadValueLength {
                        tag,
                        expected: 0,
                        got: n,
                        at,
                    });
                }
                if depth >= self.limits.max_collection_depth {
                    return Err(CodecError::CollectionTooDeep);
                }
                let (members, ended) = self.members(depth + 1)?;
                if matches!(ended, CollectionEnd::EndOfMessage) {
                    // Message terminator arrived inside a collection —
                    // the whole message is finished (see `members()`).
                    self.msg_done = true;
                }
                Ok(Value::Collection(members))
            }
            tags::TEXTLANG | tags::NAMELANG => {
                self.account_string(n, at)?;
                let data = self.take(n)?;
                let mut c = 0usize;
                if data.len() < 2 {
                    return Err(CodecError::BadValueLength {
                        tag,
                        expected: 2,
                        got: n,
                        at,
                    });
                }
                let llen = usize::from(u16::from_be_bytes([data[c], data[c + 1]]));
                c += 2;
                let need_after_lang = c.saturating_add(llen).saturating_add(2);
                if data.len() < need_after_lang {
                    return Err(CodecError::BadValueLength {
                        tag,
                        expected: need_after_lang,
                        got: n,
                        at,
                    });
                }
                let lang = Text(data[c..c + llen].to_vec());
                c += llen;
                let tlen = usize::from(u16::from_be_bytes([data[c], data[c + 1]]));
                c += 2;
                let need_after_text = c.saturating_add(tlen);
                if data.len() < need_after_text {
                    return Err(CodecError::BadValueLength {
                        tag,
                        expected: need_after_text,
                        got: n,
                        at,
                    });
                }
                let text = Text(data[c..c + tlen].to_vec());
                if tag == tags::TEXTLANG {
                    Ok(Value::TextWithLanguage { lang, text })
                } else {
                    Ok(Value::NameWithLanguage { lang, text })
                }
            }
            tags::TEXT
            | tags::NAME
            | tags::KEYWORD
            | tags::URI
            | tags::URISCHEME
            | tags::CHARSET
            | tags::LANGUAGE
            | tags::MIMETYPE => {
                self.account_string(n, at)?;
                let t = Text(self.take(n)?.to_vec());
                Ok(match tag {
                    tags::TEXT => Value::Text(t),
                    tags::NAME => Value::Name(t),
                    tags::KEYWORD => Value::Keyword(t),
                    tags::URI => Value::Uri(t),
                    tags::URISCHEME => Value::UriScheme(t),
                    tags::CHARSET => Value::Charset(t),
                    tags::LANGUAGE => Value::NaturalLanguage(t),
                    _ => Value::MimeMediaType(t),
                })
            }
            tags::RESERVED_STRING => {
                self.account_string(n, at)?;
                Ok(Value::ReservedString(self.take(n)?.to_vec()))
            }
            // Extension and any unrecognized tag → opaque bytes.
            _ => {
                self.account_string(n, at)?;
                Ok(Value::UnknownValue {
                    tag,
                    data: self.take(n)?.to_vec(),
                })
            }
        }
    }

    /// Read collection members until `endCollection` (or a message-level
    /// terminator, which ends the whole message per libcups).
    fn members(&mut self, depth: usize) -> Result<(Vec<Attribute>, CollectionEnd), CodecError> {
        let mut members: Vec<Attribute> = Vec::new();
        let mut current: Option<usize> = None;

        loop {
            let at = self.pos;
            let tag = self.u8()?;

            match tag {
                tags::END => return Ok((members, CollectionEnd::EndOfMessage)),
                tags::END_COLLECTION => {
                    // Same framing as any attribute: name-len then
                    // value-len. Inside a collection a non-empty name
                    // is the "named attribute" error path.
                    let namelen = usize::from(self.u16()?);
                    if namelen != 0 {
                        return Err(CodecError::NamedAttributeInCollection { at });
                    }
                    let n = usize::from(self.u16()?);
                    if n != 0 {
                        return Err(CodecError::CollectionValueNotEmpty { at });
                    }
                    return Ok((members, CollectionEnd::EndCollection));
                }
                tags::ZERO | tags::OPERATION => {
                    return Err(CodecError::InvalidGroupTag { tag, at });
                }
                t if tags::is_group_tag(t) => {
                    return Err(CodecError::GroupTagInCollection { tag: t, at });
                }
                tags::MEMBERNAME => {
                    let namelen = usize::from(self.u16()?);
                    if namelen != 0 {
                        return Err(CodecError::MemberNameNotEmpty { at });
                    }
                    let vlen = usize::from(self.u16()?);
                    if vlen == 0 {
                        return Err(CodecError::MemberNameEmptyValue { at });
                    }
                    if vlen > MAX_NAME_LEN {
                        return Err(CodecError::LengthOverflow {
                            field: "name",
                            len: vlen,
                            at,
                        });
                    }
                    let name = self.take(vlen)?;
                    if !is_valid_keyword(name) {
                        return Err(CodecError::InvalidName { at });
                    }
                    self.count_attr(at)?;
                    members.push(Attribute::new(Text(name.to_vec()), tags::ZERO, Vec::new()));
                    current = Some(members.len() - 1);
                }
                _ => {
                    let namelen = usize::from(self.u16()?);
                    if namelen != 0 {
                        return Err(CodecError::NamedAttributeInCollection { at });
                    }
                    let idx = current.ok_or(CodecError::ValueWithoutAttribute { at })?;
                    let member = &mut members[idx];
                    self.read_and_append(member, tag, at, depth)?;
                }
            }
        }
    }
}

fn out_of_band_value(tag: u8) -> Value {
    match tag {
        tags::UNSUPPORTED => Value::Unsupported,
        tags::DEFAULT => Value::Default,
        tags::UNKNOWN => Value::Unknown,
        tags::NOVALUE => Value::NoValue,
        tags::NOTSETTABLE => Value::NotSettable,
        tags::DELETEATTR => Value::DeleteAttr,
        _ => Value::AdminDefine,
    }
}

/// RFC 8011 §5.1.4 keyword check used for attribute and member names:
/// non-empty ASCII alphanumeric plus `-`, `.`, `_`; max 255 bytes.
fn is_valid_keyword(s: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
}
