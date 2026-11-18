//! `cups-dbus` — `org.cups.cupsd.Notifier` D-Bus signal publisher.
//!
//! Emits standard CUPS D-Bus signals (`/org/cups/cupsd/Notifier` on interface
//! `org.cups.cupsd.Notifier`) directly over the D-Bus Unix domain socket wire
//! protocol v1 with zero external runtime dependencies.
//!
//! When the system D-Bus socket (`/run/dbus/system_bus_socket`) is absent or
//! unreachable (for example inside minimal containers), [`Notifier::connect_system`]
//! gracefully degrades to a no-op publisher so `cupsd` never fails to boot.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

/// Default Linux system D-Bus Unix socket path.
pub const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";
/// CUPS D-Bus notifier object path.
pub const OBJECT_PATH: &str = "/org/cups/cupsd/Notifier";
/// CUPS D-Bus notifier interface name.
pub const INTERFACE: &str = "org.cups.cupsd.Notifier";

const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_IFACE: &str = "org.freedesktop.DBus";
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Server lifecycle signals on `org.cups.cupsd.Notifier` (signature `"s"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerEventKind {
    /// `ServerStarted`
    Started,
    /// `ServerStopped`
    Stopped,
    /// `ServerRestarted`
    Restarted,
    /// `ServerAudit`
    Audit,
}

impl ServerEventKind {
    /// D-Bus signal member name.
    #[must_use]
    pub const fn member(self) -> &'static str {
        match self {
            Self::Started => "ServerStarted",
            Self::Stopped => "ServerStopped",
            Self::Restarted => "ServerRestarted",
            Self::Audit => "ServerAudit",
        }
    }
}

/// Printer lifecycle/state signals on `org.cups.cupsd.Notifier` (signature `"sssusb"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrinterEventKind {
    /// `PrinterAdded`
    Added,
    /// `PrinterDeleted`
    Deleted,
    /// `PrinterModified`
    Modified,
    /// `PrinterRestarted`
    Restarted,
    /// `PrinterShutdown`
    Shutdown,
    /// `PrinterStopped`
    Stopped,
    /// `PrinterStateChanged`
    StateChanged,
}

impl PrinterEventKind {
    /// D-Bus signal member name.
    #[must_use]
    pub const fn member(self) -> &'static str {
        match self {
            Self::Added => "PrinterAdded",
            Self::Deleted => "PrinterDeleted",
            Self::Modified => "PrinterModified",
            Self::Restarted => "PrinterRestarted",
            Self::Shutdown => "PrinterShutdown",
            Self::Stopped => "PrinterStopped",
            Self::StateChanged => "PrinterStateChanged",
        }
    }
}

/// Job lifecycle/state signals on `org.cups.cupsd.Notifier` (signature `"sssusbuussu"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobEventKind {
    /// `JobCreated`
    Created,
    /// `JobCompleted`
    Completed,
    /// `JobState`
    State,
    /// `JobConfigChanged`
    ConfigChanged,
    /// `JobProgress`
    Progress,
}

impl JobEventKind {
    /// D-Bus signal member name.
    #[must_use]
    pub const fn member(self) -> &'static str {
        match self {
            Self::Created => "JobCreated",
            Self::Completed => "JobCompleted",
            Self::State => "JobState",
            Self::ConfigChanged => "JobConfigChanged",
            Self::Progress => "JobProgress",
        }
    }
}

/// Payload for printer D-Bus signals (matches upstream `notifier/dbus.c` `"sssusb"`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrinterSignalPayload {
    /// Human-readable notification text.
    pub text: String,
    /// Printer URI (e.g. `ipp://localhost/printers/office`).
    pub printer_uri: String,
    /// Printer queue name.
    pub printer_name: String,
    /// IPP `printer-state` enum (3 = idle, 4 = processing, 5 = stopped).
    pub printer_state: u32,
    /// Comma-separated `printer-state-reasons`.
    pub printer_state_reasons: String,
    /// Whether the printer is accepting jobs.
    pub printer_is_accepting_jobs: bool,
}

/// Payload for job D-Bus signals (matches upstream `notifier/dbus.c` `"sssusbuussu"`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobSignalPayload {
    /// Printer context fields shared with printer signals.
    pub printer: PrinterSignalPayload,
    /// IPP `job-id`.
    pub job_id: u32,
    /// IPP `job-state` enum.
    pub job_state: u32,
    /// Comma-separated `job-state-reasons`.
    pub job_state_reasons: String,
    /// Job title (`job-name`).
    pub job_name: String,
    /// `job-impressions-completed`.
    pub job_impressions_completed: u32,
}

/// A CUPS D-Bus signal ready for marshaling or emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CupsSignal {
    /// Server-level signal (`"s"`).
    Server {
        /// Specific server signal kind.
        kind: ServerEventKind,
        /// Human-readable message text.
        text: String,
    },
    /// Printer-level signal (`"sssusb"`).
    Printer {
        /// Specific printer signal kind.
        kind: PrinterEventKind,
        /// Printer fields.
        payload: PrinterSignalPayload,
    },
    /// Job-level signal (`"sssusbuussu"`).
    Job {
        /// Specific job signal kind.
        kind: JobEventKind,
        /// Job + printer fields.
        payload: JobSignalPayload,
    },
}

impl CupsSignal {
    /// D-Bus signal member name.
    #[must_use]
    pub const fn member(&self) -> &'static str {
        match self {
            Self::Server { kind, .. } => kind.member(),
            Self::Printer { kind, .. } => kind.member(),
            Self::Job { kind, .. } => kind.member(),
        }
    }

    /// D-Bus body type signature.
    #[must_use]
    pub const fn signature(&self) -> &'static str {
        match self {
            Self::Server { .. } => "s",
            Self::Printer { .. } => "sssusb",
            Self::Job { .. } => "sssusbuussu",
        }
    }

    /// Marshal this signal into a complete D-Bus v1 wire message.
    #[must_use]
    pub fn marshal(&self, serial: u32) -> Vec<u8> {
        let mut body = wire::BodyWriter::new();
        match self {
            Self::Server { text, .. } => {
                body.write_string(text);
            }
            Self::Printer { payload, .. } => {
                write_printer_payload(&mut body, payload);
            }
            Self::Job { payload, .. } => {
                write_printer_payload(&mut body, &payload.printer);
                body.write_u32(payload.job_id);
                body.write_u32(payload.job_state);
                body.write_string(&payload.job_state_reasons);
                body.write_string(&payload.job_name);
                body.write_u32(payload.job_impressions_completed);
            }
        }
        wire::marshal_signal(
            OBJECT_PATH,
            INTERFACE,
            self.member(),
            self.signature(),
            &body.into_bytes(),
            serial,
        )
    }
}

fn write_printer_payload(w: &mut wire::BodyWriter, p: &PrinterSignalPayload) {
    w.write_string(&p.text);
    w.write_string(&p.printer_uri);
    w.write_string(&p.printer_name);
    w.write_u32(p.printer_state);
    w.write_string(&p.printer_state_reasons);
    w.write_bool(p.printer_is_accepting_jobs);
}

/// D-Bus wire protocol v1 marshaling and unmarshaling helpers.
pub mod wire {
    use std::io;

    /// D-Bus message types (spec §Message Format).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum MessageType {
        /// `METHOD_CALL` (1)
        MethodCall = 1,
        /// `METHOD_RETURN` (2)
        MethodReturn = 2,
        /// `ERROR` (3)
        Error = 3,
        /// `SIGNAL` (4)
        Signal = 4,
    }

    impl MessageType {
        /// Convert from wire byte.
        #[must_use]
        pub const fn from_byte(b: u8) -> Option<Self> {
            match b {
                1 => Some(Self::MethodCall),
                2 => Some(Self::MethodReturn),
                3 => Some(Self::Error),
                4 => Some(Self::Signal),
                _ => None,
            }
        }
    }

    /// Header flag: sender does not expect a reply.
    pub const FLAG_NO_REPLY_EXPECTED: u8 = 0x01;

    /// Header field codes.
    pub const FIELD_PATH: u8 = 1;
    /// Interface name field code.
    pub const FIELD_INTERFACE: u8 = 2;
    /// Member name field code.
    pub const FIELD_MEMBER: u8 = 3;
    /// Error name field code.
    pub const FIELD_ERROR_NAME: u8 = 4;
    /// Reply serial field code.
    pub const FIELD_REPLY_SERIAL: u8 = 5;
    /// Destination field code.
    pub const FIELD_DESTINATION: u8 = 6;
    /// Sender field code.
    pub const FIELD_SENDER: u8 = 7;
    /// Body signature field code.
    pub const FIELD_SIGNATURE: u8 = 8;

    /// Little-endian D-Bus body serializer.
    #[derive(Debug, Default)]
    pub struct BodyWriter {
        buf: Vec<u8>,
    }

    impl BodyWriter {
        /// Create an empty writer.
        #[must_use]
        pub fn new() -> Self {
            Self { buf: Vec::new() }
        }

        /// Pad buffer with zero bytes to `align` (power of 2).
        pub fn align(&mut self, align: usize) {
            let rem = self.buf.len() % align;
            if rem != 0 {
                self.buf.resize(self.buf.len() + (align - rem), 0);
            }
        }

        /// Write a `BYTE` (`y`).
        pub fn write_byte(&mut self, v: u8) {
            self.buf.push(v);
        }

        /// Write a `UINT32` (`u`) aligned to 4 bytes.
        pub fn write_u32(&mut self, v: u32) {
            self.align(4);
            self.buf.extend_from_slice(&v.to_le_bytes());
        }

        /// Write a `BOOLEAN` (`b`) encoded as `0u32` or `1u32`.
        pub fn write_bool(&mut self, v: bool) {
            self.write_u32(u32::from(v));
        }

        /// Write a `STRING` (`s`) or `OBJECT_PATH` (`o`), stripping any interior NULs.
        pub fn write_string(&mut self, s: &str) {
            let clean: std::borrow::Cow<'_, str> = if s.contains('\0') {
                std::borrow::Cow::Owned(s.replace('\0', ""))
            } else {
                std::borrow::Cow::Borrowed(s)
            };
            let bytes = clean.as_bytes();
            let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            self.write_u32(len);
            self.buf.extend_from_slice(&bytes[..len as usize]);
            self.buf.push(0);
        }

        /// Write a `SIGNATURE` (`g`) (`u8` length + ASCII + NUL).
        pub fn write_signature(&mut self, sig: &str) {
            let bytes = sig.as_bytes();
            let len = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
            self.buf.push(len);
            self.buf.extend_from_slice(&bytes[..usize::from(len)]);
            self.buf.push(0);
        }

        /// Consume and return the marshaled bytes.
        #[must_use]
        pub fn into_bytes(self) -> Vec<u8> {
            self.buf
        }
    }

    fn push_header_field_str(fields: &mut BodyWriter, code: u8, variant_sig: &str, value: &str) {
        fields.align(8);
        fields.write_byte(code);
        fields.write_signature(variant_sig);
        if variant_sig == "g" {
            fields.write_signature(value);
        } else {
            fields.write_string(value);
        }
    }

    fn finish_message(
        msg_type: MessageType,
        flags: u8,
        serial: u32,
        fields_bytes: &[u8],
        body: &[u8],
    ) -> Vec<u8> {
        let body_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
        let fields_len = u32::try_from(fields_bytes.len()).unwrap_or(u32::MAX);
        let serial = if serial == 0 { 1 } else { serial };

        let mut out = Vec::with_capacity(16 + fields_bytes.len() + 8 + body.len());
        out.push(b'l'); // little-endian
        out.push(msg_type as u8);
        out.push(flags);
        out.push(1); // D-Bus protocol version 1
        out.extend_from_slice(&body_len.to_le_bytes());
        out.extend_from_slice(&serial.to_le_bytes());
        out.extend_from_slice(&fields_len.to_le_bytes());
        out.extend_from_slice(fields_bytes);
        // Header must be padded to an 8-byte boundary before the body.
        let rem = out.len() % 8;
        if rem != 0 {
            out.resize(out.len() + (8 - rem), 0);
        }
        out.extend_from_slice(body);
        out
    }

    /// Marshal a D-Bus `SIGNAL` message.
    #[must_use]
    pub fn marshal_signal(
        path: &str,
        interface: &str,
        member: &str,
        signature: &str,
        body: &[u8],
        serial: u32,
    ) -> Vec<u8> {
        let mut fields = BodyWriter::new();
        push_header_field_str(&mut fields, FIELD_PATH, "o", path);
        push_header_field_str(&mut fields, FIELD_INTERFACE, "s", interface);
        push_header_field_str(&mut fields, FIELD_MEMBER, "s", member);
        if !signature.is_empty() {
            push_header_field_str(&mut fields, FIELD_SIGNATURE, "g", signature);
        }
        finish_message(
            MessageType::Signal,
            FLAG_NO_REPLY_EXPECTED,
            serial,
            &fields.into_bytes(),
            body,
        )
    }

    /// Marshal an `org.freedesktop.DBus.Hello` `METHOD_CALL` message.
    #[must_use]
    pub fn marshal_hello(serial: u32) -> Vec<u8> {
        let mut fields = BodyWriter::new();
        push_header_field_str(&mut fields, FIELD_PATH, "o", super::DBUS_PATH);
        push_header_field_str(&mut fields, FIELD_INTERFACE, "s", super::DBUS_IFACE);
        push_header_field_str(&mut fields, FIELD_MEMBER, "s", "Hello");
        push_header_field_str(&mut fields, FIELD_DESTINATION, "s", super::DBUS_IFACE);
        finish_message(
            MessageType::MethodCall,
            0,
            serial,
            &fields.into_bytes(),
            &[],
        )
    }

    /// Marshal a `METHOD_RETURN` message carrying a single string (used for replies/tests).
    #[must_use]
    pub fn marshal_method_return_string(reply_serial: u32, serial: u32, value: &str) -> Vec<u8> {
        let mut fields = BodyWriter::new();
        fields.align(8);
        fields.write_byte(FIELD_REPLY_SERIAL);
        fields.write_signature("u");
        fields.write_u32(reply_serial);
        push_header_field_str(&mut fields, FIELD_SIGNATURE, "g", "s");
        let mut body = BodyWriter::new();
        body.write_string(value);
        finish_message(
            MessageType::MethodReturn,
            0,
            serial,
            &fields.into_bytes(),
            &body.into_bytes(),
        )
    }

    /// Decoded D-Bus v1 message header + raw body bytes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DecodedMessage {
        /// Message type.
        pub msg_type: MessageType,
        /// Header flags.
        pub flags: u8,
        /// Message serial number.
        pub serial: u32,
        /// Little-endian (`true`) or big-endian (`false`).
        pub little_endian: bool,
        /// `PATH` header field.
        pub path: Option<String>,
        /// `INTERFACE` header field.
        pub interface: Option<String>,
        /// `MEMBER` header field.
        pub member: Option<String>,
        /// `DESTINATION` header field.
        pub destination: Option<String>,
        /// `SENDER` header field.
        pub sender: Option<String>,
        /// `ERROR_NAME` header field.
        pub error_name: Option<String>,
        /// `REPLY_SERIAL` header field.
        pub reply_serial: Option<u32>,
        /// `SIGNATURE` header field.
        pub signature: Option<String>,
        /// Raw body bytes.
        pub body: Vec<u8>,
    }

    /// Reader for decoding D-Bus message bodies.
    pub struct BodyReader<'a> {
        buf: &'a [u8],
        pos: usize,
        le: bool,
    }

    impl<'a> BodyReader<'a> {
        /// Create a reader over `buf` with the given endianness.
        #[must_use]
        pub const fn new(buf: &'a [u8], little_endian: bool) -> Self {
            Self {
                buf,
                pos: 0,
                le: little_endian,
            }
        }

        fn align(&mut self, align: usize) -> io::Result<()> {
            let rem = self.pos % align;
            if rem != 0 {
                let pad = align - rem;
                if self.buf.len().saturating_sub(self.pos) < pad {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated padding",
                    ));
                }
                self.pos += pad;
            }
            Ok(())
        }

        /// Read a single byte (`y`).
        pub fn read_byte(&mut self) -> io::Result<u8> {
            let b = *self
                .buf
                .get(self.pos)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated byte"))?;
            self.pos += 1;
            Ok(b)
        }

        /// Read a `UINT32` (`u`).
        pub fn read_u32(&mut self) -> io::Result<u32> {
            self.align(4)?;
            let slice = self
                .buf
                .get(self.pos..self.pos + 4)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated u32"))?;
            self.pos += 4;
            let arr = [slice[0], slice[1], slice[2], slice[3]];
            Ok(if self.le {
                u32::from_le_bytes(arr)
            } else {
                u32::from_be_bytes(arr)
            })
        }

        /// Read a `BOOLEAN` (`b`).
        pub fn read_bool(&mut self) -> io::Result<bool> {
            match self.read_u32()? {
                0 => Ok(false),
                1 => Ok(true),
                other => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid D-Bus boolean {other}"),
                )),
            }
        }

        /// Read a `STRING` (`s`) or `OBJECT_PATH` (`o`).
        pub fn read_string(&mut self) -> io::Result<String> {
            let len = self.read_u32()? as usize;
            let end = self
                .pos
                .checked_add(len)
                .and_then(|v| v.checked_add(1))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "string length overflow")
                })?;
            let slice = self
                .buf
                .get(self.pos..end)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated string"))?;
            if slice[len] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing string NUL terminator",
                ));
            }
            let s = std::str::from_utf8(&slice[..len])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .to_string();
            self.pos = end;
            Ok(s)
        }

        /// Read a `SIGNATURE` (`g`).
        pub fn read_signature(&mut self) -> io::Result<String> {
            let len = usize::from(self.read_byte()?);
            let end = self.pos + len + 1;
            let slice = self.buf.get(self.pos..end).ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "truncated signature")
            })?;
            if slice[len] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing signature NUL terminator",
                ));
            }
            let s = std::str::from_utf8(&slice[..len])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .to_string();
            self.pos = end;
            Ok(s)
        }
    }

    /// Decode a complete D-Bus v1 wire message from `bytes`.
    pub fn decode_message(bytes: &[u8]) -> io::Result<DecodedMessage> {
        if bytes.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "D-Bus header shorter than 16 bytes",
            ));
        }
        let le = match bytes[0] {
            b'l' => true,
            b'B' => false,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid D-Bus endian byte 0x{other:02x}"),
                ));
            }
        };
        let msg_type = MessageType::from_byte(bytes[1]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown D-Bus message type {}", bytes[1]),
            )
        })?;
        let flags = bytes[2];
        if bytes[3] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported D-Bus protocol version {}", bytes[3]),
            ));
        }
        let read_u32 = |off: usize| -> u32 {
            let arr = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
            if le {
                u32::from_le_bytes(arr)
            } else {
                u32::from_be_bytes(arr)
            }
        };
        let body_len = read_u32(4) as usize;
        let serial = read_u32(8);
        let fields_len = read_u32(12) as usize;

        let fields_end = 16usize
            .checked_add(fields_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fields length overflow"))?;
        let header_padded = (fields_end + 7) & !7;
        let total_len = header_padded
            .checked_add(body_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message length overflow"))?;
        if bytes.len() < total_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated D-Bus message",
            ));
        }

        let mut msg = DecodedMessage {
            msg_type,
            flags,
            serial,
            little_endian: le,
            path: None,
            interface: None,
            member: None,
            destination: None,
            sender: None,
            error_name: None,
            reply_serial: None,
            signature: None,
            body: bytes[header_padded..total_len].to_vec(),
        };

        let mut fr = BodyReader::new(&bytes[16..fields_end], le);
        decode_header_fields(&mut fr, fields_len, &mut msg)?;
        Ok(msg)
    }

    fn decode_header_fields(
        fr: &mut BodyReader<'_>,
        fields_len: usize,
        msg: &mut DecodedMessage,
    ) -> io::Result<()> {
        while fr.pos < fields_len {
            fr.align(8)?;
            if fr.pos >= fields_len {
                break;
            }
            let code = fr.read_byte()?;
            let sig = fr.read_signature()?;
            match (code, sig.as_str()) {
                (FIELD_PATH, "o") => msg.path = Some(fr.read_string()?),
                (FIELD_INTERFACE, "s") => msg.interface = Some(fr.read_string()?),
                (FIELD_MEMBER, "s") => msg.member = Some(fr.read_string()?),
                (FIELD_ERROR_NAME, "s") => msg.error_name = Some(fr.read_string()?),
                (FIELD_DESTINATION, "s") => msg.destination = Some(fr.read_string()?),
                (FIELD_SENDER, "s") => msg.sender = Some(fr.read_string()?),
                (FIELD_SIGNATURE, "g") => msg.signature = Some(fr.read_signature()?),
                (FIELD_REPLY_SERIAL, "u") => msg.reply_serial = Some(fr.read_u32()?),
                (_, "s" | "o") => {
                    let _ = fr.read_string()?;
                }
                (_, "u") => {
                    let _ = fr.read_u32()?;
                }
                (_, "g") => {
                    let _ = fr.read_signature()?;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported header field {code} with signature '{sig}'"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Read one framed D-Bus v1 message from `r`.
    pub fn read_message<R: io::Read>(r: &mut R) -> io::Result<DecodedMessage> {
        let mut head = [0u8; 16];
        r.read_exact(&mut head)?;
        let le = match head[0] {
            b'l' => true,
            b'B' => false,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid D-Bus endian byte 0x{other:02x}"),
                ));
            }
        };
        let rd = |off: usize| -> usize {
            let arr = [head[off], head[off + 1], head[off + 2], head[off + 3]];
            (if le {
                u32::from_le_bytes(arr)
            } else {
                u32::from_be_bytes(arr)
            }) as usize
        };
        let body_len = rd(4);
        let fields_len = rd(12);
        // Cap single bus reply read to 1 MiB to protect against hostile peers.
        if fields_len > 64 * 1024 || body_len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "D-Bus message exceeds size cap",
            ));
        }
        let header_padded = (16 + fields_len + 7) & !7;
        let rest_len = (header_padded - 16) + body_len;
        let mut full = Vec::with_capacity(16 + rest_len);
        full.extend_from_slice(&head);
        full.resize(16 + rest_len, 0);
        r.read_exact(&mut full[16..])?;
        decode_message(&full)
    }
}

/// Parse a `DBUS_SYSTEM_BUS_ADDRESS`-style address string and return the first
/// `unix:path=...` socket path, if present.
#[must_use]
pub fn parse_bus_address(addr: &str) -> Option<PathBuf> {
    for entry in addr.split(';') {
        let Some(params) = entry.trim().strip_prefix("unix:") else {
            continue;
        };
        for kv in params.split(',') {
            if let Some(raw_path) = kv.strip_prefix("path=") {
                if !raw_path.is_empty() {
                    return Some(PathBuf::from(unescape_bus_value(raw_path)));
                }
            }
        }
    }
    None
}

fn unescape_bus_value(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn current_uid_hex() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_euid_hex_from_status(&status)
}

fn parse_euid_hex_from_status(status: &str) -> Option<String> {
    let uid_line = status.lines().find(|l| l.starts_with("Uid:"))?;
    let euid = uid_line.split_whitespace().nth(2)?;
    let mut hex = String::with_capacity(euid.len() * 2);
    for b in euid.bytes() {
        let _ = write!(hex, "{b:02x}");
    }
    Some(hex)
}

#[cfg(unix)]
struct BusConn {
    stream: UnixStream,
    unique_name: String,
    next_serial: u32,
}

#[cfg(not(unix))]
struct BusConn {
    unique_name: String,
    next_serial: u32,
}

/// Thread-safe `org.cups.cupsd.Notifier` D-Bus publisher.
///
/// Degrades cleanly to a no-op when no system D-Bus daemon is available.
pub struct Notifier {
    conn: Mutex<Option<BusConn>>,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let connected = self.is_connected();
        f.debug_struct("Notifier")
            .field("connected", &connected)
            .finish()
    }
}

impl Notifier {
    /// Create a no-op notifier that silently discards all emitted signals.
    #[must_use]
    pub fn noop() -> Self {
        Self {
            conn: Mutex::new(None),
        }
    }

    /// Connect to the system D-Bus (`$DBUS_SYSTEM_BUS_ADDRESS` or
    /// `/run/dbus/system_bus_socket`).
    ///
    /// Never fails: if the bus socket is absent or authentication fails (e.g.
    /// inside containers), returns a no-op [`Notifier`] where
    /// [`Self::is_connected`] is `false`.
    #[must_use]
    pub fn connect_system() -> Self {
        let path = std::env::var("DBUS_SYSTEM_BUS_ADDRESS")
            .ok()
            .and_then(|v| parse_bus_address(&v))
            .unwrap_or_else(|| PathBuf::from(SYSTEM_BUS_SOCKET));
        Self::connect_path(&path).unwrap_or_else(|_| Self::noop())
    }

    /// Connect to an explicit Unix-socket D-Bus daemon and perform the SASL
    /// `EXTERNAL` + `org.freedesktop.DBus.Hello` handshake.
    #[cfg(unix)]
    pub fn connect_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;

        // D-Bus Unix transport requires a leading NUL byte followed by SASL.
        stream.write_all(&[0])?;
        let auth_cmd = match current_uid_hex() {
            Some(hex) => format!("AUTH EXTERNAL {hex}\r\n"),
            None => "AUTH EXTERNAL\r\n".to_string(),
        };
        stream.write_all(auth_cmd.as_bytes())?;
        stream.flush()?;

        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if !line.starts_with("OK ") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("D-Bus SASL auth rejected: {}", line.trim()),
            ));
        }
        stream.write_all(b"BEGIN\r\n")?;
        stream.flush()?;

        // Send Hello (serial 1) and wait for METHOD_RETURN with our unique bus name.
        let hello = wire::marshal_hello(1);
        stream.write_all(&hello)?;
        stream.flush()?;

        let reply = read_hello_reply(&mut reader)?;
        Ok(Self {
            conn: Mutex::new(Some(BusConn {
                stream,
                unique_name: reply,
                next_serial: 2,
            })),
        })
    }

    /// Connect stub for non-Unix platforms (always returns `Unsupported`).
    #[cfg(not(unix))]
    pub fn connect_path(_path: impl AsRef<Path>) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "D-Bus Unix sockets require Unix",
        ))
    }

    /// `true` when backed by an active D-Bus daemon connection.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    /// Unique D-Bus connection name returned by `Hello` (e.g. `":1.42"`).
    #[must_use]
    pub fn unique_name(&self) -> Option<String> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|c| c.unique_name.clone())
    }

    /// Emit a [`CupsSignal`] on the bus.
    ///
    /// Returns `Ok(false)` in no-op/disconnected mode, `Ok(true)` if written
    /// to the bus, or `Err` (and transitions cleanly to disconnected) if the
    /// socket fails.
    #[cfg(unix)]
    pub fn emit(&self, signal: &CupsSignal) -> io::Result<bool> {
        let mut guard = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(conn) = guard.as_mut() else {
            return Ok(false);
        };
        let serial = conn.next_serial;
        conn.next_serial = conn.next_serial.wrapping_add(1).max(1);
        let wire_bytes = signal.marshal(serial);
        if let Err(e) = conn
            .stream
            .write_all(&wire_bytes)
            .and_then(|()| conn.stream.flush())
        {
            *guard = None;
            return Err(e);
        }
        Ok(true)
    }

    /// Emit stub for non-Unix platforms.
    #[cfg(not(unix))]
    pub fn emit(&self, _signal: &CupsSignal) -> io::Result<bool> {
        Ok(false)
    }

    /// Convenience helper to emit a server signal.
    pub fn emit_server(&self, kind: ServerEventKind, text: impl Into<String>) -> io::Result<bool> {
        self.emit(&CupsSignal::Server {
            kind,
            text: text.into(),
        })
    }

    /// Convenience helper to emit a printer signal.
    pub fn emit_printer(
        &self,
        kind: PrinterEventKind,
        payload: PrinterSignalPayload,
    ) -> io::Result<bool> {
        self.emit(&CupsSignal::Printer { kind, payload })
    }

    /// Convenience helper to emit a job signal.
    pub fn emit_job(&self, kind: JobEventKind, payload: JobSignalPayload) -> io::Result<bool> {
        self.emit(&CupsSignal::Job { kind, payload })
    }
}

#[cfg(unix)]
fn read_hello_reply<R: Read>(r: &mut R) -> io::Result<String> {
    // Allow a small number of unsolicited signals (e.g. NameAcquired) before Hello reply.
    for _ in 0..8 {
        let msg = wire::read_message(r)?;
        match msg.msg_type {
            wire::MessageType::MethodReturn if msg.reply_serial == Some(1) => {
                let mut br = wire::BodyReader::new(&msg.body, msg.little_endian);
                return br.read_string();
            }
            wire::MessageType::Error if msg.reply_serial == Some(1) => {
                return Err(io::Error::other(format!(
                    "D-Bus Hello error: {}",
                    msg.error_name.as_deref().unwrap_or("unknown")
                )));
            }
            _ => {}
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "D-Bus Hello reply not received",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_sock(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "presswork-dbus-test-{}-{label}-{id}.sock",
            std::process::id()
        ))
    }

    #[test]
    fn signal_members_and_signatures() {
        let server_cases = [
            (ServerEventKind::Started, "ServerStarted"),
            (ServerEventKind::Stopped, "ServerStopped"),
            (ServerEventKind::Restarted, "ServerRestarted"),
            (ServerEventKind::Audit, "ServerAudit"),
        ];
        for (kind, name) in server_cases {
            let sig = CupsSignal::Server {
                kind,
                text: "msg".into(),
            };
            assert_eq!(sig.member(), name);
            assert_eq!(sig.signature(), "s");
        }

        let printer_cases = [
            (PrinterEventKind::Added, "PrinterAdded"),
            (PrinterEventKind::Deleted, "PrinterDeleted"),
            (PrinterEventKind::Modified, "PrinterModified"),
            (PrinterEventKind::Restarted, "PrinterRestarted"),
            (PrinterEventKind::Shutdown, "PrinterShutdown"),
            (PrinterEventKind::Stopped, "PrinterStopped"),
            (PrinterEventKind::StateChanged, "PrinterStateChanged"),
        ];
        for (kind, name) in printer_cases {
            let sig = CupsSignal::Printer {
                kind,
                payload: PrinterSignalPayload::default(),
            };
            assert_eq!(sig.member(), name);
            assert_eq!(sig.signature(), "sssusb");
        }

        let job_cases = [
            (JobEventKind::Created, "JobCreated"),
            (JobEventKind::Completed, "JobCompleted"),
            (JobEventKind::State, "JobState"),
            (JobEventKind::ConfigChanged, "JobConfigChanged"),
            (JobEventKind::Progress, "JobProgress"),
        ];
        for (kind, name) in job_cases {
            let sig = CupsSignal::Job {
                kind,
                payload: JobSignalPayload::default(),
            };
            assert_eq!(sig.member(), name);
            assert_eq!(sig.signature(), "sssusbuussu");
        }
    }

    #[test]
    fn marshal_and_decode_all_signal_types() {
        // 1. Server signal (also checks NUL stripping).
        let s_sig = CupsSignal::Server {
            kind: ServerEventKind::Started,
            text: "cupsd\0started".into(),
        };
        let raw = s_sig.marshal(0); // serial 0 promoted to 1
        let dec = wire::decode_message(&raw).unwrap();
        assert_eq!(dec.msg_type, wire::MessageType::Signal);
        assert_eq!(dec.flags, wire::FLAG_NO_REPLY_EXPECTED);
        assert_eq!(dec.serial, 1);
        assert_eq!(dec.path.as_deref(), Some(OBJECT_PATH));
        assert_eq!(dec.interface.as_deref(), Some(INTERFACE));
        assert_eq!(dec.member.as_deref(), Some("ServerStarted"));
        assert_eq!(dec.signature.as_deref(), Some("s"));
        let mut br = wire::BodyReader::new(&dec.body, dec.little_endian);
        assert_eq!(br.read_string().unwrap(), "cupsdstarted");

        // 2. Printer signal.
        let p_sig = CupsSignal::Printer {
            kind: PrinterEventKind::Added,
            payload: PrinterSignalPayload {
                text: "Printer office added".into(),
                printer_uri: "ipp://localhost:631/printers/office".into(),
                printer_name: "office".into(),
                printer_state: 3,
                printer_state_reasons: "none".into(),
                printer_is_accepting_jobs: true,
            },
        };
        let raw = p_sig.marshal(7);
        let dec = wire::decode_message(&raw).unwrap();
        assert_eq!(dec.member.as_deref(), Some("PrinterAdded"));
        assert_eq!(dec.signature.as_deref(), Some("sssusb"));
        let mut br = wire::BodyReader::new(&dec.body, dec.little_endian);
        assert_eq!(br.read_string().unwrap(), "Printer office added");
        assert_eq!(
            br.read_string().unwrap(),
            "ipp://localhost:631/printers/office"
        );
        assert_eq!(br.read_string().unwrap(), "office");
        assert_eq!(br.read_u32().unwrap(), 3);
        assert_eq!(br.read_string().unwrap(), "none");
        assert!(br.read_bool().unwrap());

        // 3. Job signal.
        let j_sig = CupsSignal::Job {
            kind: JobEventKind::Completed,
            payload: JobSignalPayload {
                printer: PrinterSignalPayload {
                    text: "Job #42 completed".into(),
                    printer_uri: "ipp://localhost:631/printers/office".into(),
                    printer_name: "office".into(),
                    printer_state: 3,
                    printer_state_reasons: "none".into(),
                    printer_is_accepting_jobs: false,
                },
                job_id: 42,
                job_state: 9,
                job_state_reasons: "job-completed-successfully".into(),
                job_name: "report.pdf".into(),
                job_impressions_completed: 5,
            },
        };
        let raw = j_sig.marshal(9);
        let dec = wire::decode_message(&raw).unwrap();
        assert_eq!(dec.member.as_deref(), Some("JobCompleted"));
        assert_eq!(dec.signature.as_deref(), Some("sssusbuussu"));
        let mut br = wire::BodyReader::new(&dec.body, dec.little_endian);
        assert_eq!(br.read_string().unwrap(), "Job #42 completed");
        assert_eq!(
            br.read_string().unwrap(),
            "ipp://localhost:631/printers/office"
        );
        assert_eq!(br.read_string().unwrap(), "office");
        assert_eq!(br.read_u32().unwrap(), 3);
        assert_eq!(br.read_string().unwrap(), "none");
        assert!(!br.read_bool().unwrap());
        assert_eq!(br.read_u32().unwrap(), 42);
        assert_eq!(br.read_u32().unwrap(), 9);
        assert_eq!(br.read_string().unwrap(), "job-completed-successfully");
        assert_eq!(br.read_string().unwrap(), "report.pdf");
        assert_eq!(br.read_u32().unwrap(), 5);
    }

    #[test]
    fn parse_bus_address_and_uid_status() {
        assert_eq!(
            parse_bus_address("unix:path=/run/dbus/system_bus_socket"),
            Some(PathBuf::from("/run/dbus/system_bus_socket"))
        );
        assert_eq!(
            parse_bus_address("tcp:host=127.0.0.1;unix:abstract=/tmp/x,path=/tmp/my%20bus.sock"),
            Some(PathBuf::from("/tmp/my bus.sock"))
        );
        assert_eq!(parse_bus_address("unix:path="), None);
        assert_eq!(parse_bus_address("tcp:host=localhost"), None);

        let fake_status = "Name:\tcupsd\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(
            parse_euid_hex_from_status(fake_status).as_deref(),
            Some("31303030")
        );
        assert!(current_uid_hex().is_some());
    }

    #[test]
    fn noop_and_missing_socket_degrade_gracefully() {
        let noop = Notifier::noop();
        assert!(!noop.is_connected());
        assert_eq!(noop.unique_name(), None);
        assert!(format!("{noop:?}").contains("connected: false"));
        assert!(!noop.emit_server(ServerEventKind::Started, "ok").unwrap());

        let missing = unique_sock("missing");
        assert!(Notifier::connect_path(&missing).is_err());

        // connect_system never panics even when bus is unavailable or available.
        let _sys = Notifier::connect_system();
    }

    #[test]
    fn mock_dbus_daemon_handshake_and_emit() {
        let sock = unique_sock("mock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut nul = [0u8; 1];
            conn.read_exact(&mut nul).unwrap();
            assert_eq!(nul[0], 0);

            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut auth = String::new();
            reader.read_line(&mut auth).unwrap();
            assert!(auth.starts_with("AUTH EXTERNAL"));

            conn.write_all(b"OK 0123456789abcdef\r\n").unwrap();
            conn.flush().unwrap();

            let mut begin = String::new();
            reader.read_line(&mut begin).unwrap();
            assert_eq!(begin, "BEGIN\r\n");

            // Read Hello method call.
            let hello = wire::read_message(&mut reader).unwrap();
            assert_eq!(hello.msg_type, wire::MessageType::MethodCall);
            assert_eq!(hello.member.as_deref(), Some("Hello"));
            assert_eq!(hello.destination.as_deref(), Some(DBUS_IFACE));

            // Send unsolicited NameAcquired signal first, then METHOD_RETURN.
            let extra = wire::marshal_signal(DBUS_PATH, DBUS_IFACE, "NameAcquired", "", &[], 1);
            conn.write_all(&extra).unwrap();
            let reply = wire::marshal_method_return_string(hello.serial, 2, ":1.77");
            conn.write_all(&reply).unwrap();
            conn.flush().unwrap();

            // Receive three emitted CUPS signals.
            let m1 = wire::read_message(&mut reader).unwrap();
            let m2 = wire::read_message(&mut reader).unwrap();
            let m3 = wire::read_message(&mut reader).unwrap();
            (m1, m2, m3)
        });

        let notifier = Notifier::connect_path(&sock).unwrap();
        assert!(notifier.is_connected());
        assert_eq!(notifier.unique_name().as_deref(), Some(":1.77"));
        assert!(format!("{notifier:?}").contains("connected: true"));

        assert!(notifier
            .emit_server(ServerEventKind::Started, "boot")
            .unwrap());
        assert!(notifier
            .emit_printer(
                PrinterEventKind::Modified,
                PrinterSignalPayload {
                    printer_name: "laser".into(),
                    ..Default::default()
                },
            )
            .unwrap());
        assert!(notifier
            .emit_job(
                JobEventKind::Created,
                JobSignalPayload {
                    job_id: 11,
                    ..Default::default()
                },
            )
            .unwrap());

        let (m1, m2, m3) = server.join().unwrap();
        assert_eq!(m1.member.as_deref(), Some("ServerStarted"));
        assert_eq!(m2.member.as_deref(), Some("PrinterModified"));
        assert_eq!(m3.member.as_deref(), Some("JobCreated"));

        // Server thread closed socket; next emit fails cleanly and marks disconnected.
        assert!(notifier
            .emit_server(ServerEventKind::Stopped, "bye")
            .is_err());
        assert!(!notifier.is_connected());
        assert!(!notifier
            .emit_server(ServerEventKind::Stopped, "bye2")
            .unwrap());

        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn mock_dbus_auth_rejected_and_hello_error() {
        // Case 1: SASL rejected.
        let sock1 = unique_sock("rej");
        let _ = std::fs::remove_file(&sock1);
        let l1 = UnixListener::bind(&sock1).unwrap();
        let t1 = std::thread::spawn(move || {
            let (mut c, _) = l1.accept().unwrap();
            let mut nul = [0u8; 1];
            let _ = c.read_exact(&mut nul);
            let mut r = BufReader::new(c.try_clone().unwrap());
            let mut line = String::new();
            let _ = r.read_line(&mut line);
            let _ = c.write_all(b"REJECTED EXTERNAL\r\n");
        });
        assert!(Notifier::connect_path(&sock1).is_err());
        t1.join().unwrap();
        let _ = std::fs::remove_file(&sock1);

        // Case 2: Hello returns ERROR message.
        let sock2 = unique_sock("err");
        let _ = std::fs::remove_file(&sock2);
        let l2 = UnixListener::bind(&sock2).unwrap();
        let t2 = std::thread::spawn(move || {
            let (mut c, _) = l2.accept().unwrap();
            let mut nul = [0u8; 1];
            let _ = c.read_exact(&mut nul);
            let mut r = BufReader::new(c.try_clone().unwrap());
            let mut line = String::new();
            let _ = r.read_line(&mut line);
            let _ = c.write_all(b"OK 1234\r\n");
            line.clear();
            let _ = r.read_line(&mut line);
            let _ = wire::read_message(&mut r).unwrap();
            // Craft an ERROR reply with reply_serial = 1.
            let mut fields = wire::BodyWriter::new();
            fields.align(8);
            fields.write_byte(wire::FIELD_ERROR_NAME);
            fields.write_signature("s");
            fields.write_string("org.freedesktop.DBus.Error.Failed");
            fields.align(8);
            fields.write_byte(wire::FIELD_REPLY_SERIAL);
            fields.write_signature("u");
            fields.write_u32(1);
            fields.align(8);
            fields.write_byte(wire::FIELD_SENDER);
            fields.write_signature("s");
            fields.write_string("org.freedesktop.DBus");
            let fb = fields.into_bytes();
            let mut msg = vec![b'l', wire::MessageType::Error as u8, 0, 1];
            msg.extend_from_slice(&0u32.to_le_bytes());
            msg.extend_from_slice(&2u32.to_le_bytes());
            msg.extend_from_slice(&(u32::try_from(fb.len()).unwrap()).to_le_bytes());
            msg.extend_from_slice(&fb);
            while msg.len() % 8 != 0 {
                msg.push(0);
            }
            let _ = c.write_all(&msg);
        });
        assert!(Notifier::connect_path(&sock2).is_err());
        t2.join().unwrap();
        let _ = std::fs::remove_file(&sock2);
    }

    #[test]
    fn wire_decode_validation_and_big_endian() {
        assert!(wire::decode_message(&[0u8; 4]).is_err());
        assert!(wire::decode_message(&[b'x'; 16]).is_err());
        assert!(
            wire::decode_message(&[b'l', 99, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]).is_err()
        );
        assert!(
            wire::decode_message(&[b'l', 4, 0, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]).is_err()
        );
        assert!(
            wire::decode_message(&[b'l', 4, 0, 1, 10, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]).is_err()
        );

        // Big-endian empty signal message.
        let be = [
            b'B', 4, 1, 1, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let dec = wire::decode_message(&be).unwrap();
        assert!(!dec.little_endian);
        assert_eq!(dec.serial, 5);
        let mut br = wire::BodyReader::new(&dec.body, false);
        assert!(br.read_bool().unwrap());

        // Invalid boolean value in body.
        let mut bad_bool = wire::BodyReader::new(&[2, 0, 0, 0], true);
        assert!(bad_bool.read_bool().is_err());

        // Missing NUL terminator in string / signature.
        let mut bad_str = wire::BodyReader::new(&[1, 0, 0, 0, b'a', b'X'], true);
        assert!(bad_str.read_string().is_err());
        let mut bad_sig = wire::BodyReader::new(&[1, b's', b'X'], true);
        assert!(bad_sig.read_signature().is_err());

        // Oversized message rejected in read_message.
        let mut big = [0u8; 16];
        big[0] = b'l';
        big[1] = 4;
        big[3] = 1;
        big[12..16].copy_from_slice(&(100_000u32).to_le_bytes());
        assert!(wire::read_message(&mut &big[..]).is_err());

        // Invalid endian byte & big-endian read_message.
        let mut bad_end = [0u8; 16];
        bad_end[0] = b'?';
        assert!(wire::read_message(&mut &bad_end[..]).is_err());
        let be_msg = wire::read_message(&mut &be[..]).unwrap();
        assert!(!be_msg.little_endian);

        // Truncated padding / string / signature in BodyReader.
        let mut trunc_pad = wire::BodyReader::new(&[1u8, 2], true);
        let _ = trunc_pad.read_byte().unwrap();
        assert!(trunc_pad.read_u32().is_err());
        let mut trunc_str = wire::BodyReader::new(&[10, 0, 0, 0, b'a'], true);
        assert!(trunc_str.read_string().is_err());
        let mut trunc_sig = wire::BodyReader::new(&[5, b's'], true);
        assert!(trunc_sig.read_signature().is_err());

        // Unknown header fields ("s", "u", "g") skipped; unknown signature rejected.
        let mut custom_fields = wire::BodyWriter::new();
        custom_fields.align(8);
        custom_fields.write_byte(99);
        custom_fields.write_signature("s");
        custom_fields.write_string("extra");
        custom_fields.align(8);
        custom_fields.write_byte(98);
        custom_fields.write_signature("u");
        custom_fields.write_u32(7);
        custom_fields.align(8);
        custom_fields.write_byte(97);
        custom_fields.write_signature("g");
        custom_fields.write_signature("y");
        let fb = custom_fields.into_bytes();
        let mut pkt = vec![b'l', 4, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0];
        pkt.extend_from_slice(&(u32::try_from(fb.len()).unwrap()).to_le_bytes());
        pkt.extend_from_slice(&fb);
        while pkt.len() % 8 != 0 {
            pkt.push(0);
        }
        assert!(wire::decode_message(&pkt).is_ok());

        let mut bad_field = wire::BodyWriter::new();
        bad_field.align(8);
        bad_field.write_byte(99);
        bad_field.write_signature("t");
        let bfb = bad_field.into_bytes();
        let mut bad_pkt = vec![b'l', 4, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0];
        bad_pkt.extend_from_slice(&(u32::try_from(bfb.len()).unwrap()).to_le_bytes());
        bad_pkt.extend_from_slice(&bfb);
        while bad_pkt.len() % 8 != 0 {
            bad_pkt.push(0);
        }
        assert!(wire::decode_message(&bad_pkt).is_err());

        // read_hello_reply fails cleanly if no reply arrives within 8 messages.
        let mut flood = Vec::new();
        for s in 1..=8 {
            flood.extend_from_slice(&wire::marshal_signal(
                DBUS_PATH,
                DBUS_IFACE,
                "Ping",
                "",
                &[],
                s,
            ));
        }
        assert!(read_hello_reply(&mut &flood[..]).is_err());
    }
}
