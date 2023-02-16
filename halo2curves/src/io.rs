//! Just enough piece of std::io to support running halo2 in no_std mode
//! TODO: maybe we should use alloc
use alloc::fmt;

pub type Error = &'static str;

pub type Result<T> = core::result::Result<T, Error>;

pub trait Read {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()>;
}

impl Read for &[u8] {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.len() > self.len() {
            return Err("failed to fill whole buffer");
        }
        let (a, b) = self.split_at(buf.len());

        // First check if the amount of bytes we want to read is small:
        // `copy_from_slice` will generally expand to a call to `memcpy`, and
        // for a single byte the overhead is significant.
        if buf.len() == 1 {
            buf[0] = a[0];
        } else {
            buf.copy_from_slice(a);
        }

        *self = b;
        Ok(())
    }
}

pub trait Write {
    fn write(&mut self, data: &[u8]) -> Result<usize>;
    fn write_all(&mut self, data: &[u8]) -> Result<()>;
    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> Result<()> {
        // Create a shim which translates a Write to a fmt::Write and saves
        // off I/O errors. instead of discarding them
        struct Adapter<'a, T: ?Sized + 'a> {
            inner: &'a mut T,
            error: Result<()>,
        }

        impl<T: Write + ?Sized> fmt::Write for Adapter<'_, T> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                match self.inner.write_all(s.as_bytes()) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.error = Err(e);
                        Err(fmt::Error)
                    }
                }
            }
        }

        let mut output = Adapter {
            inner: self,
            error: Ok(()),
        };
        match fmt::write(&mut output, fmt) {
            Ok(()) => Ok(()),
            Err(..) => {
                // check if the error came from the underlying `Write` or not
                if output.error.is_err() {
                    output.error
                } else {
                    Err("formatter error")
                }
            }
        }
    }
}

impl Write for &mut [u8] {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        let amt = core::cmp::min(data.len(), self.len());
        let (a, b) = core::mem::replace(self, &mut []).split_at_mut(amt);
        a.copy_from_slice(&data[..amt]);
        *self = b;
        Ok(amt)
    }

    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        if self.write(data)? == data.len() {
            Ok(())
        } else {
            Err("failed to write whole buffer")
        }
    }
}

impl Write for alloc::vec::Vec<u8> {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        let len = data.len();
        self.extend_from_slice(data);
        Ok(len)
    }

    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let data_wrote = self.write(data)?;
        if data_wrote == data.len() {
            Ok(())
        } else {
            Err("failed to write whole buffer")
        }
    }
}
