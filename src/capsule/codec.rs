use bytes::{Buf, BufMut};

use crate::error::DecodeError;

/// Maximum value encodable as a QUIC variable-length integer: 2^62 - 1.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Returns the encoded length in bytes for a given value.
pub fn varint_len(val: u64) -> Result<usize, DecodeError> {
    if val <= 63 {
        Ok(1)
    } else if val <= 16383 {
        Ok(2)
    } else if val <= 1_073_741_823 {
        Ok(4)
    } else if val <= VARINT_MAX {
        Ok(8)
    } else {
        Err(DecodeError::InvalidVarInt)
    }
}

/// Read a QUIC-style variable-length integer (RFC 9000 §16).
pub fn read_varint(buf: &mut impl Buf) -> Result<u64, DecodeError> {
    if !buf.has_remaining() {
        return Err(DecodeError::Underflow);
    }

    let first = buf.get_u8();
    let len = 1usize << (first >> 6);

    if buf.remaining() < len - 1 {
        return Err(DecodeError::Underflow);
    }

    let mut val = (first & 0x3f) as u64;
    for _ in 1..len {
        val = (val << 8) | buf.get_u8() as u64;
    }

    Ok(val)
}

/// Write a QUIC-style variable-length integer (RFC 9000 §16).
pub fn write_varint(buf: &mut impl BufMut, val: u64) -> Result<(), DecodeError> {
    let len = varint_len(val)?;
    match len {
        1 => {
            buf.put_u8(val as u8);
        }
        2 => {
            buf.put_u8(0x40 | (val >> 8) as u8);
            buf.put_u8(val as u8);
        }
        4 => {
            buf.put_u8(0x80 | (val >> 24) as u8);
            buf.put_u8((val >> 16) as u8);
            buf.put_u8((val >> 8) as u8);
            buf.put_u8(val as u8);
        }
        8 => {
            buf.put_u8(0xc0 | (val >> 56) as u8);
            buf.put_u8((val >> 48) as u8);
            buf.put_u8((val >> 40) as u8);
            buf.put_u8((val >> 32) as u8);
            buf.put_u8((val >> 24) as u8);
            buf.put_u8((val >> 16) as u8);
            buf.put_u8((val >> 8) as u8);
            buf.put_u8(val as u8);
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn roundtrip(val: u64) {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, val).unwrap();
        assert_eq!(buf.len(), varint_len(val).unwrap());
        let decoded = read_varint(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_zero() {
        roundtrip(0);
    }

    #[test]
    fn test_one_byte_max() {
        roundtrip(63);
    }

    #[test]
    fn test_two_byte_min() {
        roundtrip(64);
    }

    #[test]
    fn test_two_byte_max() {
        roundtrip(16383);
    }

    #[test]
    fn test_four_byte_min() {
        roundtrip(16384);
    }

    #[test]
    fn test_four_byte_max() {
        roundtrip(1_073_741_823);
    }

    #[test]
    fn test_eight_byte_min() {
        roundtrip(1_073_741_824);
    }

    #[test]
    fn test_eight_byte_max() {
        roundtrip(VARINT_MAX);
    }

    #[test]
    fn test_encoding_lengths() {
        assert_eq!(varint_len(0).unwrap(), 1);
        assert_eq!(varint_len(63).unwrap(), 1);
        assert_eq!(varint_len(64).unwrap(), 2);
        assert_eq!(varint_len(16383).unwrap(), 2);
        assert_eq!(varint_len(16384).unwrap(), 4);
        assert_eq!(varint_len(1_073_741_823).unwrap(), 4);
        assert_eq!(varint_len(1_073_741_824).unwrap(), 8);
        assert_eq!(varint_len(VARINT_MAX).unwrap(), 8);
    }

    #[test]
    fn test_overflow_rejected() {
        assert!(varint_len(VARINT_MAX + 1).is_err());
        let mut buf = BytesMut::new();
        assert!(write_varint(&mut buf, VARINT_MAX + 1).is_err());
    }

    #[test]
    fn test_underflow_empty_buffer() {
        let mut buf = &[][..];
        assert!(matches!(read_varint(&mut buf), Err(DecodeError::Underflow)));
    }

    #[test]
    fn test_underflow_truncated() {
        // A 2-byte varint header (0x40) but only 1 byte in buffer
        let mut buf = &[0x40][..];
        assert!(matches!(read_varint(&mut buf), Err(DecodeError::Underflow)));
    }

    #[test]
    fn test_rfc9000_examples() {
        // RFC 9000 §A.1 sample encodings
        let cases: &[(&[u8], u64)] = &[
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for &(encoded, expected) in cases {
            let mut cursor = &encoded[..];
            let decoded = read_varint(&mut cursor).unwrap();
            assert_eq!(decoded, expected);

            // Verify our encoder produces the same bytes
            let mut buf = BytesMut::new();
            write_varint(&mut buf, expected).unwrap();
            assert_eq!(&buf[..], encoded);
        }
    }

    #[test]
    fn test_sequential_read_write() {
        let values = [0u64, 42, 300, 100_000, 2_000_000_000];
        let mut buf = BytesMut::new();
        for &v in &values {
            write_varint(&mut buf, v).unwrap();
        }
        let mut reader = &buf[..];
        for &v in &values {
            assert_eq!(read_varint(&mut reader).unwrap(), v);
        }
        assert_eq!(reader.remaining(), 0);
    }
}
