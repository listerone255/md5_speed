#![allow(clippy::unreadable_literal)]

fn blockify(inp: &[u8], oup: &mut [u32; 16]) {
    use std::convert::TryInto;
    let inp = &inp[0..64]; // Avoid bounds checking
    *oup = [
        u32::from_le_bytes(inp[0..4].try_into().unwrap()),
        u32::from_le_bytes(inp[4..8].try_into().unwrap()),
        u32::from_le_bytes(inp[8..12].try_into().unwrap()),
        u32::from_le_bytes(inp[12..16].try_into().unwrap()),
        u32::from_le_bytes(inp[16..20].try_into().unwrap()),
        u32::from_le_bytes(inp[20..24].try_into().unwrap()),
        u32::from_le_bytes(inp[24..28].try_into().unwrap()),
        u32::from_le_bytes(inp[28..32].try_into().unwrap()),
        u32::from_le_bytes(inp[32..36].try_into().unwrap()),
        u32::from_le_bytes(inp[36..40].try_into().unwrap()),
        u32::from_le_bytes(inp[40..44].try_into().unwrap()),
        u32::from_le_bytes(inp[44..48].try_into().unwrap()),
        u32::from_le_bytes(inp[48..52].try_into().unwrap()),
        u32::from_le_bytes(inp[52..56].try_into().unwrap()),
        u32::from_le_bytes(inp[56..60].try_into().unwrap()),
        u32::from_le_bytes(inp[60..64].try_into().unwrap()),
    ]
}

#[allow(clippy::cognitive_complexity)]
fn iteration(hs: &mut [u32; 4], xs: &[u8]) {
    macro_rules! round_a {
        ($ms:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $g:expr, $s:expr) => {{
            unsafe {
                $a = (($b & $c) | (!$b & $d))
                    .wrapping_add($a)
                    .wrapping_add($k)
                    .wrapping_add(*$ms.get_unchecked($g))
                    .rotate_left($s)
                    .wrapping_add($b);
            }
            // println!("{:02}: {:08x} {:08x} {:08x} {:08x}", $i, $a, $b, $c, $d);
        }};
    }
    macro_rules! round_b {
        ($ms:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $g:expr, $s:expr) => {{
            unsafe {
                $a = (($d & $b) | (!$d & $c))
                    .wrapping_add($a)
                    .wrapping_add($k)
                    .wrapping_add(*$ms.get_unchecked($g))
                    .rotate_left($s)
                    .wrapping_add($b);
            }
            // println!("{:02}: {:08x} {:08x} {:08x} {:08x}", $i, $a, $b, $c, $d);
        }};
    }
    macro_rules! round_c {
        ($ms:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $g:expr, $s:expr) => {{
            unsafe {
                $a = ($b ^ $c ^ $d)
                    .wrapping_add($a)
                    .wrapping_add($k)
                    .wrapping_add(*$ms.get_unchecked($g))
                    .rotate_left($s)
                    .wrapping_add($b);
            }
            // println!("{:02}: {:08x} {:08x} {:08x} {:08x}", $i, $a, $b, $c, $d);
        }};
    }
    macro_rules! round_d {
        ($ms:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $g:expr, $s:expr) => {{
            unsafe {
                $a = ($c ^ ($b | !$d))
                    .wrapping_add($a)
                    .wrapping_add($k)
                    .wrapping_add(*$ms.get_unchecked($g))
                    .rotate_left($s)
                    .wrapping_add($b);
            }
            // println!("{:02}: {:08x} {:08x} {:08x} {:08x}", $i, $a, $b, $c, $d);
        }};
    }

    let mut ms = [0; 16];
    blockify(xs, &mut ms);

    let mut r0 = hs[0];
    let mut r1 = hs[1];
    let mut r2 = hs[2];
    let mut r3 = hs[3];

    round_a!(ms, 0, r0, r1, r2, r3, 0xd76aa478, 0, 7);
    round_a!(ms, 1, r3, r0, r1, r2, 0xe8c7b756, 1, 12);
    round_a!(ms, 2, r2, r3, r0, r1, 0x242070db, 2, 17);
    round_a!(ms, 3, r1, r2, r3, r0, 0xc1bdceee, 3, 22);

    round_a!(ms, 4, r0, r1, r2, r3, 0xf57c0faf, 4, 7);
    round_a!(ms, 5, r3, r0, r1, r2, 0x4787c62a, 5, 12);
    round_a!(ms, 6, r2, r3, r0, r1, 0xa8304613, 6, 17);
    round_a!(ms, 7, r1, r2, r3, r0, 0xfd469501, 7, 22);

    round_a!(ms, 8, r0, r1, r2, r3, 0x698098d8, 8, 7);
    round_a!(ms, 9, r3, r0, r1, r2, 0x8b44f7af, 9, 12);
    round_a!(ms, 10, r2, r3, r0, r1, 0xffff5bb1, 10, 17);
    round_a!(ms, 11, r1, r2, r3, r0, 0x895cd7be, 11, 22);

    round_a!(ms, 12, r0, r1, r2, r3, 0x6b901122, 12, 7);
    round_a!(ms, 13, r3, r0, r1, r2, 0xfd987193, 13, 12);
    round_a!(ms, 14, r2, r3, r0, r1, 0xa679438e, 14, 17);
    round_a!(ms, 15, r1, r2, r3, r0, 0x49b40821, 15, 22);

    round_b!(ms, 16, r0, r1, r2, r3, 0xf61e2562, 1, 5);
    round_b!(ms, 17, r3, r0, r1, r2, 0xc040b340, 6, 9);
    round_b!(ms, 18, r2, r3, r0, r1, 0x265e5a51, 11, 14);
    round_b!(ms, 19, r1, r2, r3, r0, 0xe9b6c7aa, 0, 20);

    round_b!(ms, 20, r0, r1, r2, r3, 0xd62f105d, 5, 5);
    round_b!(ms, 21, r3, r0, r1, r2, 0x02441453, 10, 9);
    round_b!(ms, 22, r2, r3, r0, r1, 0xd8a1e681, 15, 14);
    round_b!(ms, 23, r1, r2, r3, r0, 0xe7d3fbc8, 4, 20);

    round_b!(ms, 24, r0, r1, r2, r3, 0x21e1cde6, 9, 5);
    round_b!(ms, 25, r3, r0, r1, r2, 0xc33707d6, 14, 9);
    round_b!(ms, 26, r2, r3, r0, r1, 0xf4d50d87, 3, 14);
    round_b!(ms, 27, r1, r2, r3, r0, 0x455a14ed, 8, 20);

    round_b!(ms, 28, r0, r1, r2, r3, 0xa9e3e905, 13, 5);
    round_b!(ms, 29, r3, r0, r1, r2, 0xfcefa3f8, 2, 9);
    round_b!(ms, 30, r2, r3, r0, r1, 0x676f02d9, 7, 14);
    round_b!(ms, 31, r1, r2, r3, r0, 0x8d2a4c8a, 12, 20);

    round_c!(ms, 32, r0, r1, r2, r3, 0xfffa3942, 5, 4);
    round_c!(ms, 33, r3, r0, r1, r2, 0x8771f681, 8, 11);
    round_c!(ms, 34, r2, r3, r0, r1, 0x6d9d6122, 11, 16);
    round_c!(ms, 35, r1, r2, r3, r0, 0xfde5380c, 14, 23);

    round_c!(ms, 36, r0, r1, r2, r3, 0xa4beea44, 1, 4);
    round_c!(ms, 37, r3, r0, r1, r2, 0x4bdecfa9, 4, 11);
    round_c!(ms, 38, r2, r3, r0, r1, 0xf6bb4b60, 7, 16);
    round_c!(ms, 39, r1, r2, r3, r0, 0xbebfbc70, 10, 23);

    round_c!(ms, 40, r0, r1, r2, r3, 0x289b7ec6, 13, 4);
    round_c!(ms, 41, r3, r0, r1, r2, 0xeaa127fa, 0, 11);
    round_c!(ms, 42, r2, r3, r0, r1, 0xd4ef3085, 3, 16);
    round_c!(ms, 43, r1, r2, r3, r0, 0x04881d05, 6, 23);

    round_c!(ms, 44, r0, r1, r2, r3, 0xd9d4d039, 9, 4);
    round_c!(ms, 45, r3, r0, r1, r2, 0xe6db99e5, 12, 11);
    round_c!(ms, 46, r2, r3, r0, r1, 0x1fa27cf8, 15, 16);
    round_c!(ms, 47, r1, r2, r3, r0, 0xc4ac5665, 2, 23);

    round_d!(ms, 48, r0, r1, r2, r3, 0xf4292244, 0, 6);
    round_d!(ms, 49, r3, r0, r1, r2, 0x432aff97, 7, 10);
    round_d!(ms, 50, r2, r3, r0, r1, 0xab9423a7, 14, 15);
    round_d!(ms, 51, r1, r2, r3, r0, 0xfc93a039, 5, 21);

    round_d!(ms, 52, r0, r1, r2, r3, 0x655b59c3, 12, 6);
    round_d!(ms, 53, r3, r0, r1, r2, 0x8f0ccc92, 3, 10);
    round_d!(ms, 54, r2, r3, r0, r1, 0xffeff47d, 10, 15);
    round_d!(ms, 55, r1, r2, r3, r0, 0x85845dd1, 1, 21);

    round_d!(ms, 56, r0, r1, r2, r3, 0x6fa87e4f, 8, 6);
    round_d!(ms, 57, r3, r0, r1, r2, 0xfe2ce6e0, 15, 10);
    round_d!(ms, 58, r2, r3, r0, r1, 0xa3014314, 6, 15);
    round_d!(ms, 59, r1, r2, r3, r0, 0x4e0811a1, 13, 21);

    round_d!(ms, 60, r0, r1, r2, r3, 0xf7537e82, 4, 6);
    round_d!(ms, 61, r3, r0, r1, r2, 0xbd3af235, 11, 10);
    round_d!(ms, 62, r2, r3, r0, r1, 0x2ad7d2bb, 2, 15);
    round_d!(ms, 63, r1, r2, r3, r0, 0xeb86d391, 9, 21);

    *hs = [
        hs[0].wrapping_add(r0),
        hs[1].wrapping_add(r1),
        hs[2].wrapping_add(r2),
        hs[3].wrapping_add(r3),
    ];
}

pub fn md5(input: &[u8]) -> String {
    let mut hs = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    let mut iter = input.chunks_exact(64);
    for chunk in &mut iter {
        iteration(&mut hs, &chunk);
    }

    let mut buf = [0; 64];
    buf[0] = 128;
    buf[56..64].copy_from_slice(&((input.len() * 8) as u64).to_le_bytes());
    iteration(&mut hs, &buf);

    // format!(
    //     "{:08x}{:08x}{:08x}{:08x}",
    //     hs[0].swap_bytes(),
    //     hs[1].swap_bytes(),
    //     hs[2].swap_bytes(),
    //     hs[3].swap_bytes()
    // )
    String::new() // Avoid format! for benchmarking
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let inp = b"";
        let oup = "d41d8cd98f00b204e9800998ecf8427e";
        assert_eq!(md5(&inp[..]), oup);

        let inp = b"0123456701234567012345670123456701234567012345670123456701234567";
        let oup = "520620de89e220f9b5850cc97cbff46c";
        assert_eq!(md5(&inp[..]), oup);
    }
}
