//! Byte helpers and the encodings the spec's notation names: `lenStr`, `u32be`, `u64be`,
//! `b64u` (base64url, no padding) and `b32` (RFC 4648 base32, lowercase, no padding).
//! Decoders are strict: they reject padding, foreign characters and non-canonical trailing
//! bits, so one value has exactly one text form.

/// Big-endian `u32`.
pub(crate) fn u32be(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

/// Big-endian `u64`.
pub(crate) fn u64be(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}

/// Reads a big-endian `u32` at `off`, or `None` when `b` is too short.
pub(crate) fn read_u32be(b: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s: [u8; 4] = b.get(off..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(s))
}

/// Reads a big-endian `u64` at `off`, or `None` when `b` is too short.
pub(crate) fn read_u64be(b: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let s: [u8; 8] = b.get(off..end)?.try_into().ok()?;
    Some(u64::from_be_bytes(s))
}

/// `u32be(byte length of the UTF-8 encoding) || UTF-8 bytes`.
pub(crate) fn len_str(out: &mut Vec<u8>, s: &str) {
    // Every string this is used on is far shorter than 4 GiB; a longer one cannot be framed.
    let n = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&u32be(n));
    out.extend_from_slice(s.as_bytes());
}

/// Lowercase hex.
pub fn to_hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(char::from(HEX[usize::from(x >> 4)]));
        s.push(char::from(HEX[usize::from(x & 15)]));
    }
    s
}

/// Hex, either case; `None` on an odd length or a foreign character.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs.iter().map(|[h, l]| Some((nibble(*h)? << 4) | nibble(*l)?)).collect()
}

// ── base64url, no padding ──

const B64U: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64u_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// base64url without padding.
pub fn b64u(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    let sym = |v: u32| char::from(B64U[(v & 63) as usize]);
    let (chunks, rest) = b.as_chunks::<3>();
    for [x, y, z] in chunks {
        let n = (u32::from(*x) << 16) | (u32::from(*y) << 8) | u32::from(*z);
        s.push(sym(n >> 18));
        s.push(sym(n >> 12));
        s.push(sym(n >> 6));
        s.push(sym(n));
    }
    match *rest {
        [a] => {
            let n = u32::from(a) << 16;
            s.push(sym(n >> 18));
            s.push(sym(n >> 12));
        }
        [a, b] => {
            let n = (u32::from(a) << 16) | (u32::from(b) << 8);
            s.push(sym(n >> 18));
            s.push(sym(n >> 12));
            s.push(sym(n >> 6));
        }
        _ => {}
    }
    s
}

/// Strict base64url without padding: no padding, no foreign characters, zero trailing bits.
pub fn from_b64u(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in bytes {
        acc = ((acc << 6) | b64u_value(c)?) & 0xffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// Strict base64url of exactly `N` bytes.
pub fn from_b64u_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    // Reject long inputs before decoding them.
    if s.len() > N.div_ceil(3) * 4 {
        return None;
    }
    from_b64u(s)?.try_into().ok()
}

// ── base32 (RFC 4648), lowercase, no padding ──

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lowercase, no padding.
pub fn b32(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &x in b {
        acc = ((acc << 8) | u32::from(x)) & 0xffff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            s.push(char::from(B32[((acc >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        s.push(char::from(B32[((acc << (5 - bits)) & 31) as usize]));
    }
    s
}

/// Strict lowercase base32 without padding.
pub fn from_b32(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'a'..=b'z' => u32::from(c - b'a'),
            b'2'..=b'7' => u32::from(c - b'2') + 26,
            _ => return None,
        };
        acc = ((acc << 5) | v) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64u_round_trips_and_is_strict() {
        for n in 0..40 {
            let v: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(from_b64u(&b64u(&v)).as_deref(), Some(&v[..]));
        }
        assert_eq!(from_b64u("AA=="), None, "padding");
        assert_eq!(from_b64u("A"), None, "length 1 mod 4");
        assert_eq!(from_b64u("AB"), None, "non-zero trailing bits");
        assert_eq!(from_b64u("AA+A"), None, "standard alphabet");
        assert_eq!(from_b64u("AA").as_deref(), Some(&[0u8][..]));
        assert_eq!(from_b64u_array::<2>("AAA"), Some([0, 0]));
        assert_eq!(from_b64u_array::<2>("AAAA"), None);
    }

    #[test]
    fn b32_round_trips_and_is_strict() {
        for n in 0..40 {
            let v: Vec<u8> = (0..n).map(|i| (i * 53 + 7) as u8).collect();
            assert_eq!(from_b32(&b32(&v)).as_deref(), Some(&v[..]));
        }
        assert_eq!(from_b32("AA"), None, "upper case");
        assert_eq!(from_b32("ab"), None, "non-zero trailing bits");
        assert_eq!(from_b32("a"), None, "five bits are no byte");
    }

    #[test]
    fn hex_and_integers() {
        assert_eq!(to_hex(&[0, 0xab, 0xff]), "00abff");
        assert_eq!(from_hex("00ABff"), Some(vec![0, 0xab, 0xff]));
        assert_eq!(from_hex("0"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(read_u32be(&[0, 0, 1], 0), None);
        assert_eq!(read_u32be(&[9, 0, 0, 1, 2], 1), Some(258));
        assert_eq!(read_u64be(&[0; 7], 0), None);
        assert_eq!(read_u32be(&[0; 8], usize::MAX), None);
    }
}
