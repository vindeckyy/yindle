//! Terminal line settings and modem control for serial ports
//! (`tcgetattr`/`tcsetattr` + DTR/DSR modem control ioctls).

use std::os::fd::RawFd;

/// Terminal line settings for serial ports (`tcgetattr`/`tcsetattr`) —
/// owned copy of `libc::termios` with named setters so callers stay
/// `unsafe`-free.
#[derive(Clone)]
pub struct Termios {
    raw: libc::termios,
    dtrdsr: bool,
}

impl Termios {
    /// `tcgetattr(fd)` → the current settings, `None` on error.
    #[must_use]
    pub fn get(fd: RawFd) -> Option<Self> {
        // SAFETY: `termios` is a POD; all-zero is valid before `tcgetattr` fills it.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `t` is a valid out-param; `fd` may be any fd (fails harmlessly).
        if unsafe { libc::tcgetattr(fd, &raw mut t) } == 0 {
            Some(Self {
                raw: t,
                dtrdsr: false,
            })
        } else {
            None
        }
    }

    /// `tcdrain` + `tcsetattr(fd, TCSADRAIN, self)` — apply after draining.
    /// When `dtrdsr` flow control was requested via [`Self::set_flow`], also
    /// asserts DTR via `TIOCMBIS` (best-effort on devices without modem lines).
    #[must_use]
    pub fn set(&self, fd: RawFd) -> bool {
        // SAFETY: `&self.raw` is a valid in-param; `fd` may be any fd.
        let ok = unsafe {
            libc::tcdrain(fd) == 0 && libc::tcsetattr(fd, libc::TCSADRAIN, &raw const self.raw) == 0
        };
        if ok && self.dtrdsr {
            let _ = Self::set_dtr(fd, true);
        }
        ok
    }

    /// Map a numeric baud rate to a `B*` constant; `None` if unsupported.
    #[must_use]
    pub fn baud(rate: u32) -> Option<libc::speed_t> {
        Some(match rate {
            50 => libc::B50,
            75 => libc::B75,
            110 => libc::B110,
            134 => libc::B134,
            150 => libc::B150,
            200 => libc::B200,
            300 => libc::B300,
            600 => libc::B600,
            1200 => libc::B1200,
            1800 => libc::B1800,
            2400 => libc::B2400,
            4800 => libc::B4800,
            9600 => libc::B9600,
            19200 => libc::B19200,
            38_400 => libc::B38400,
            57_600 => libc::B57600,
            115_200 => libc::B115200,
            230_400 => libc::B230400,
            _ => return None,
        })
    }

    /// `cfsetispeed`/`cfsetospeed` for a `B*` constant.
    pub fn set_baud(&mut self, speed: libc::speed_t) {
        // SAFETY: `&mut self.raw` is a valid termios to update.
        unsafe {
            libc::cfsetispeed(&raw mut self.raw, speed);
            libc::cfsetospeed(&raw mut self.raw, speed);
        }
    }

    /// Parity: `none`/`odd`/`even`/`space`/`mark`.
    pub fn set_parity(&mut self, parity: &str) {
        self.raw.c_iflag &= !(libc::ISTRIP | libc::IGNPAR | libc::INPCK | libc::PARMRK);
        self.raw.c_cflag &= !libc::CMSPAR;
        match parity {
            "odd" => self.raw.c_cflag |= libc::PARENB | libc::PARODD,
            "even" => self.raw.c_cflag = (self.raw.c_cflag | libc::PARENB) & !libc::PARODD,
            "space" => {
                self.raw.c_cflag |= libc::PARENB | libc::CMSPAR;
                self.raw.c_cflag &= !libc::PARODD;
            }
            "mark" => self.raw.c_cflag |= libc::PARENB | libc::CMSPAR | libc::PARODD,
            _ => self.raw.c_cflag &= !libc::PARENB,
        }
    }

    /// Character size 5–8 bits (`CS5`…`CS8`); other values default to 8 bits.
    pub fn set_bits(&mut self, bits: &str) {
        self.raw.c_cflag &= !libc::CSIZE;
        self.raw.c_cflag |= match bits {
            "5" => libc::CS5,
            "6" => libc::CS6,
            "7" => libc::CS7,
            _ => libc::CS8,
        };
    }

    /// Flow control: `none`/`soft`(xon/xoff)/`hard`(rtscts)/`dtrdsr`.
    pub fn set_flow(&mut self, flow: &str) {
        self.dtrdsr = false;
        match flow {
            "soft" | "xon" => {
                self.raw.c_iflag |= libc::IXON | libc::IXOFF;
                self.raw.c_cflag &= !libc::CRTSCTS;
            }
            "hard" | "rtscts" => {
                self.raw.c_iflag &= !(libc::IXON | libc::IXOFF);
                self.raw.c_cflag |= libc::CRTSCTS;
            }
            "dtrdsr" => {
                self.raw.c_iflag &= !(libc::IXON | libc::IXOFF);
                self.raw.c_cflag &= !libc::CRTSCTS;
                self.dtrdsr = true;
            }
            _ => {
                self.raw.c_iflag &= !(libc::IXON | libc::IXOFF);
                self.raw.c_cflag &= !libc::CRTSCTS;
            }
        }
    }

    /// Returns `true` if `dtrdsr` flow control was configured on this `Termios`.
    #[must_use]
    pub const fn is_dtrdsr(&self) -> bool {
        self.dtrdsr
    }

    /// Read current modem status bits (`TIOCMGET`).
    #[must_use]
    pub fn get_modem_bits(fd: RawFd) -> Option<u32> {
        let mut bits: libc::c_int = 0;
        // SAFETY: `TIOCMGET` writes an `int` modem status bitmask into `bits`.
        if unsafe { libc::ioctl(fd, libc::TIOCMGET, &raw mut bits) } == 0 {
            u32::try_from(bits).ok()
        } else {
            None
        }
    }

    /// Assert (`on == true`) or clear (`on == false`) the DTR modem control line
    /// (`TIOCMBIS` / `TIOCMBIC` with `TIOCM_DTR`).
    #[must_use]
    pub fn set_dtr(fd: RawFd, on: bool) -> bool {
        let bit: libc::c_int = libc::TIOCM_DTR;
        let req = if on { libc::TIOCMBIS } else { libc::TIOCMBIC };
        // SAFETY: `TIOCMBIS`/`TIOCMBIC` reads an `int` bitmask from `&bit`.
        unsafe { libc::ioctl(fd, req, &raw const bit) == 0 }
    }

    /// Returns `true` when the DSR modem line (`TIOCM_DSR`) is asserted on `fd`.
    /// Returns `None` if modem control ioctls are unsupported on `fd`.
    #[must_use]
    pub fn is_dsr_ready(fd: RawFd) -> Option<bool> {
        let bits = Self::get_modem_bits(fd)?;
        let dsr = u32::try_from(libc::TIOCM_DSR).ok()?;
        Some((bits & dsr) != 0)
    }

    /// `tcdrain(fd)` — wait for pending output to flush.
    pub fn drain(fd: RawFd) {
        // SAFETY: `fd` may be any fd; `tcdrain` is side-effect safe.
        unsafe {
            libc::tcdrain(fd);
        }
    }
}
