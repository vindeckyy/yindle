//! CUPS backchannel pipe (`CUPS_BC_FD = 3`) and sidechannel datagram socketpair
//! (`CUPS_SC_FD = 4`) ABI types, framing codec, and safe OS channel primitives.
//!
//! Matches `cups/backchannel.h` and `cups/sidechannel.h`.

use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

/// Standard CUPS backchannel file descriptor (`CUPS_BC_FD`).
pub const CUPS_BC_FD: RawFd = 3;

/// Standard CUPS sidechannel file descriptor (`CUPS_SC_FD`).
pub const CUPS_SC_FD: RawFd = 4;

/// Maximum payload length for a CUPS sidechannel datagram (16-bit length field).
pub const CUPS_SC_MAX_DATA: usize = 65_535;

/// Header size of a CUPS sidechannel datagram (`[cmd, status, len_hi, len_lo]`).
const SC_HEADER_LEN: usize = 4;

/// Unidirectional OS pipe implementing CUPS backchannel transport
/// (backend writes -> filter reads).
#[derive(Debug)]
pub struct BackChannel {
    reader: PipeReader,
    writer: PipeWriter,
}

impl BackChannel {
    /// Allocate a fresh OS backchannel pipe.
    pub fn new() -> io::Result<Self> {
        let (reader, writer) = io::pipe()?;
        Ok(Self { reader, writer })
    }

    /// Split into `(reader, writer)` ends (filter reads, backend writes).
    #[must_use]
    pub fn split(self) -> (PipeReader, PipeWriter) {
        (self.reader, self.writer)
    }

    /// Borrow the read end.
    #[must_use]
    pub fn reader(&self) -> &PipeReader {
        &self.reader
    }

    /// Borrow the write end.
    #[must_use]
    pub fn writer(&self) -> &PipeWriter {
        &self.writer
    }

    /// Raw file descriptor of the read end.
    #[must_use]
    pub fn read_fd(&self) -> RawFd {
        self.reader.as_raw_fd()
    }

    /// Raw file descriptor of the write end.
    #[must_use]
    pub fn write_fd(&self) -> RawFd {
        self.writer.as_raw_fd()
    }

    /// Write bytes into the backchannel pipe.
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)
    }

    /// Read bytes from the backchannel pipe.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

/// `cups_sc_command_t` — CUPS sidechannel command codes (`cups/sidechannel.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SideChannelCommand {
    /// `CUPS_SC_CMD_NONE`
    None = 0,
    /// `CUPS_SC_CMD_SOFT_RESET` — soft reset the device.
    SoftReset = 1,
    /// `CUPS_SC_CMD_DRAIN_OUTPUT` — drain all pending output.
    DrainOutput = 2,
    /// `CUPS_SC_CMD_GET_BIDI` — query bidirectional capabilities.
    GetBidi = 3,
    /// `CUPS_SC_CMD_GET_DEVICE_ID` — query IEEE-1284 device ID.
    GetDeviceId = 4,
    /// `CUPS_SC_CMD_GET_STATE` — query device state bitmask.
    GetState = 5,
    /// `CUPS_SC_CMD_SNMP_GET` — query an SNMP OID.
    SnmpGet = 6,
    /// `CUPS_SC_CMD_SNMP_GET_NEXT` — walk next SNMP OID.
    SnmpGetNext = 7,
    /// `CUPS_SC_CMD_GET_CONNECTED` — query connection state.
    GetConnected = 8,
}

impl SideChannelCommand {
    /// Convert a wire byte to a [`SideChannelCommand`].
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::None,
            1 => Self::SoftReset,
            2 => Self::DrainOutput,
            3 => Self::GetBidi,
            4 => Self::GetDeviceId,
            5 => Self::GetState,
            6 => Self::SnmpGet,
            7 => Self::SnmpGetNext,
            8 => Self::GetConnected,
            _ => return None,
        })
    }

    /// Encode to wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// `cups_sc_status_t` — CUPS sidechannel status codes (`cups/sidechannel.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SideChannelStatus {
    /// `CUPS_SC_STATUS_NONE`
    None = 0,
    /// `CUPS_SC_STATUS_OK`
    Ok = 1,
    /// `CUPS_SC_STATUS_IO_ERROR`
    IoError = 2,
    /// `CUPS_SC_STATUS_TIMEOUT`
    Timeout = 3,
    /// `CUPS_SC_STATUS_NO_RESPONSE`
    NoResponse = 4,
    /// `CUPS_SC_STATUS_BAD_MESSAGE`
    BadMessage = 5,
    /// `CUPS_SC_STATUS_TOO_BIG`
    TooBig = 6,
    /// `CUPS_SC_STATUS_NOT_IMPLEMENTED`
    NotImplemented = 7,
}

impl SideChannelStatus {
    /// Convert a wire byte to a [`SideChannelStatus`].
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::None,
            1 => Self::Ok,
            2 => Self::IoError,
            3 => Self::Timeout,
            4 => Self::NoResponse,
            5 => Self::BadMessage,
            6 => Self::TooBig,
            7 => Self::NotImplemented,
            _ => return None,
        })
    }

    /// Encode to wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One CUPS sidechannel datagram message (`[cmd, status, len_hi, len_lo, data...]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideChannelMessage {
    /// Sidechannel command.
    pub command: SideChannelCommand,
    /// Sidechannel status (`Ok` on responses, `None` on requests).
    pub status: SideChannelStatus,
    /// Message payload bytes.
    pub data: Vec<u8>,
}

impl SideChannelMessage {
    /// Construct a new request message (`status = None`).
    #[must_use]
    pub fn request(command: SideChannelCommand, data: Vec<u8>) -> Self {
        Self {
            command,
            status: SideChannelStatus::None,
            data,
        }
    }

    /// Construct a new response message.
    #[must_use]
    pub fn response(command: SideChannelCommand, status: SideChannelStatus, data: Vec<u8>) -> Self {
        Self {
            command,
            status,
            data,
        }
    }

    /// Encode to CUPS sidechannel wire format (`[cmd, status, len_hi, len_lo, data...]`).
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let len = u16::try_from(self.data.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "sidechannel payload exceeds 65535 bytes",
            )
        })?;
        let mut out = Vec::with_capacity(SC_HEADER_LEN + self.data.len());
        out.push(self.command.as_u8());
        out.push(self.status.as_u8());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Decode from CUPS sidechannel wire format.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < SC_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidechannel datagram shorter than 4-byte header",
            ));
        }
        let command = SideChannelCommand::from_u8(bytes[0]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown sidechannel command {}", bytes[0]),
            )
        })?;
        let status = SideChannelStatus::from_u8(bytes[1]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown sidechannel status {}", bytes[1]),
            )
        })?;
        let declared_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let actual_len = bytes.len() - SC_HEADER_LEN;
        if declared_len != actual_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sidechannel length mismatch: declared {declared_len}, got {actual_len}"),
            ));
        }
        Ok(Self {
            command,
            status,
            data: bytes[SC_HEADER_LEN..].to_vec(),
        })
    }
}

/// One endpoint of a CUPS sidechannel `AF_UNIX` `SOCK_DGRAM` socketpair.
#[derive(Debug)]
pub struct SideChannelEnd {
    sock: UnixDatagram,
}

impl SideChannelEnd {
    /// Raw file descriptor of this socketpair endpoint.
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    /// Send one encoded [`SideChannelMessage`] datagram to the peer endpoint.
    pub fn send(&self, msg: &SideChannelMessage) -> io::Result<()> {
        let encoded = msg.encode()?;
        let written = self.sock.send(&encoded)?;
        if written != encoded.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short sidechannel datagram write",
            ));
        }
        Ok(())
    }

    /// Receive one [`SideChannelMessage`] datagram, with an optional read timeout.
    pub fn recv(&self, timeout: Option<Duration>) -> io::Result<SideChannelMessage> {
        self.sock.set_read_timeout(timeout)?;
        let mut buf = vec![0u8; SC_HEADER_LEN + CUPS_SC_MAX_DATA];
        let n = self.sock.recv(&mut buf)?;
        SideChannelMessage::decode(&buf[..n])
    }

    /// Perform a synchronous request/response round-trip (`cupsSideChannelDoRequest`).
    pub fn do_request(
        &self,
        command: SideChannelCommand,
        data: &[u8],
        timeout: Duration,
    ) -> io::Result<SideChannelMessage> {
        self.send(&SideChannelMessage::request(command, data.to_vec()))?;
        let reply = self.recv(Some(timeout))?;
        if reply.command != command {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "sidechannel reply command mismatch: expected {:?}, got {:?}",
                    command, reply.command
                ),
            ));
        }
        Ok(reply)
    }
}

/// Bidirectional `AF_UNIX` `SOCK_DGRAM` socketpair implementing CUPS sidechannel
/// communication between filters and backend.
#[derive(Debug)]
pub struct SideChannel {
    filter_end: SideChannelEnd,
    backend_end: SideChannelEnd,
}

impl SideChannel {
    /// Allocate a fresh connected `AF_UNIX` `SOCK_DGRAM` socketpair.
    pub fn new() -> io::Result<Self> {
        let (a, b) = UnixDatagram::pair()?;
        Ok(Self {
            filter_end: SideChannelEnd { sock: a },
            backend_end: SideChannelEnd { sock: b },
        })
    }

    /// Split into `(filter_end, backend_end)`.
    #[must_use]
    pub fn split(self) -> (SideChannelEnd, SideChannelEnd) {
        (self.filter_end, self.backend_end)
    }

    /// Borrow the filter-side endpoint.
    #[must_use]
    pub fn filter_end(&self) -> &SideChannelEnd {
        &self.filter_end
    }

    /// Borrow the backend-side endpoint.
    #[must_use]
    pub fn backend_end(&self) -> &SideChannelEnd {
        &self.backend_end
    }
}
