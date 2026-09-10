//! Shared bounds-checked wire reader for GeoIP and GeoSite protobuf databases.
const WIRE_VARINT: u32 = 0;
const WIRE_LEN_DELIM: u32 = 2;
const WIRE_I64: u32 = 1;
const WIRE_I32: u32 = 5;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("geodata protobuf: truncated at offset {0}")]
    Truncated(usize),
    #[error("geodata protobuf: varint overflow at offset {0}")]
    VarintOverflow(usize),
    #[error("geodata protobuf: invalid utf-8 in field at offset {0}")]
    InvalidUtf8(usize),
    #[error("geodata protobuf: unknown wire type {1} at offset {0}")]
    UnknownWireType(usize, u32),
}

/// Wire-format primitives shared by the GeoIP and GeoSite schemas.
pub(crate) struct PbReader<'a> {
    buf: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> PbReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(crate) fn is_at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn read_varint(&mut self) -> Result<u64, WireError> {
        let start = self.pos;
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if self.pos >= self.buf.len() {
                return Err(WireError::Truncated(start));
            }
            let b = self.buf[self.pos];
            self.pos += 1;
            if shift >= 64 || (shift == 63 && b > 1) {
                return Err(WireError::VarintOverflow(start));
            }
            result |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    /// Read a wire tag — returns `(field_number, wire_type)`.
    pub(crate) fn read_tag(&mut self) -> Result<(u32, u32), WireError> {
        let tag = self.read_varint()?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u32;
        Ok((field, wire))
    }

    pub(crate) fn read_length_delimited(&mut self) -> Result<&'a [u8], WireError> {
        let start = self.pos;
        let len = self.read_varint()? as usize;
        if self.remaining() < len {
            return Err(WireError::Truncated(start));
        }
        let bytes = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    /// Skip a field whose tag was just consumed. Required when an unknown
    /// field is encountered (e.g. `Domain.attribute`, field 3 wire-type 2).
    pub(crate) fn skip_field(&mut self, wire: u32) -> Result<(), WireError> {
        let start = self.pos;
        match wire {
            WIRE_VARINT => {
                let _ = self.read_varint()?;
            }
            WIRE_LEN_DELIM => {
                let _ = self.read_length_delimited()?;
            }
            WIRE_I64 => {
                if self.remaining() < 8 {
                    return Err(WireError::Truncated(start));
                }
                self.pos += 8;
            }
            WIRE_I32 => {
                if self.remaining() < 4 {
                    return Err(WireError::Truncated(start));
                }
                self.pos += 4;
            }
            other => return Err(WireError::UnknownWireType(start, other)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_bounds_reject_overflow_and_truncation() {
        let mut maximal = [0xff; 10];
        maximal[9] = 1;
        assert_eq!(PbReader::new(&maximal).read_varint().unwrap(), u64::MAX);
        maximal[9] = 2;
        assert!(matches!(
            PbReader::new(&maximal).read_varint(),
            Err(WireError::VarintOverflow(_))
        ));
        assert!(matches!(
            PbReader::new(&[0x80]).read_varint(),
            Err(WireError::Truncated(_))
        ));
    }
}
