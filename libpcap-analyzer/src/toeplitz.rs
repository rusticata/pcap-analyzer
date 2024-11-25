use std::ops::Deref;

/// Maximum key size used throughout.  It's OK for hardware to use only the
/// first 16 bytes, which is all that's required for IPv4.
pub const RSS_KEYSIZE: usize = 40;

#[repr(align(8))]
pub struct AlignedU8<const SZ: usize>(pub [u8; SZ]);

pub fn try_align32_slice_u8(input: &[u8]) -> Option<&[u32]> {
    let (_prefix, data, _suffix) = unsafe { input.align_to::<u32>() };
    if _prefix.is_empty() && _suffix.is_empty() {
        Some(data)
    } else {
        None
    }
}

impl<const SZ: usize> AlignedU8<SZ> {
    pub fn align32(&self) -> &[u32] {
        // this will always succeed since the structure is annotated with `repr(align(4))`
        let (_prefix, data, _suffix) = unsafe { self.0.align_to::<u32>() };
        data
    }
}

impl<const SZ: usize> AsRef<[u8]> for AlignedU8<SZ> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const SZ: usize> Deref for AlignedU8<SZ> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

// original Microsoft's key
#[rustfmt::skip]
pub const DEFAULT_KEY : AlignedU8<52> = AlignedU8([
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
]);

pub const DEFAULT_KEY_U32: &[u32] = &[
    0xda565a6d, 0xc20e5b25, 0x3d256741, 0xb08fa343, 0xcb2bcad0, 0xb4307bae, 0xa32dcb77, 0xcf23080,
    0x3bb7426a, 0xfa01acbe, 0x0, 0x0, 0x0,
];

pub const DEFAULT_KEY_U32BE: &[u32] = &[
    0x6d5a56da, 0x255b0ec2, 0x4167253d, 0x43a38fb0, 0xd0ca2bcb, 0xae7b30b4, 0x77cb2da3, 0x8030f20c,
    0x6a42b73b, 0xbeac01fa, 0x0, 0x0, 0x0,
];

// key from http://www.ndsl.kaist.edu/~shinae/papers/TR-symRSS.pdf
//
// Let’s assume we have a frame IP source: 1.1.1.1, IP destination: 2.2.2.2 and UDP port 22 to udp
// port 55. This means that the input for the hash function of the 4 tuples will be:
// [1.1.1.1][2.2.2.2][22][55] and for the opposite direction: [2.2.2.2][1.1.1.1][55][22]. To
// support the same hash value for these two inputs, the first 32bit of the key need to be
// identical to the second 32bit, and the 16bit afterwards should be identical to the next 16bit.
#[rustfmt::skip]
pub const SYMMETRIC_KEY : AlignedU8<52> = AlignedU8([
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
]);

pub const SYMMETRIC_KEY_U32BE: &[u32] = &[
    0x6d5a6d5a, 0x6d5a6d5a, 0x6d5a6d5a, 0x6d5a6d5a, 0x6d5a6d5a, 0x6d5a6d5a, 0x6d5a6d5a, 0x6d5a6d5a,
    0x6d5a6d5a, 0x6d5a6d5a, 0x0, 0x0, 0x0,
];

/// Toeplitz (RSS) hash algorithm
pub fn toeplitz_hash(key: &[u8], data: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    let mut v = (u32::from(key[0]) << 24)
        | (u32::from(key[1]) << 16)
        | (u32::from(key[2]) << 8)
        | u32::from(key[3]);
    for i in 0..data.len() {
        for b in 0..8 {
            if data[i] & (1 << (7 - b)) != 0 {
                hash ^= v;
            }
            v <<= 1;
            if (i + 4) < RSS_KEYSIZE && (key[i + 4] & (1 << (7 - b))) != 0 {
                v |= 1;
            }
        }
    }
    hash
}

/// Toeplitz (RSS) hash algorithm, optimized if key and buffer and 32-bits aligned
pub fn toeplitz_hash_aligned32(key: &[u8], data: &[u8]) -> u32 {
    let (_prefix, data32, _suffix) = unsafe { data.align_to::<u32>() };
    debug_assert_eq!(_prefix.len(), 0, "data is not aligned properly");
    debug_assert_eq!(_suffix.len(), 0, "input data length not a multiple of 4");
    let (_prefix, key32, _suffix) = unsafe { key.align_to::<u32>() };
    debug_assert_eq!(_prefix.len(), 0, "key is not aligned properly");
    debug_assert_eq!(_suffix.len(), 0, "key length not a multiple of 4");
    let mut hash: u32 = 0;
    for j in 0..data32.len() {
        let mut map = data32[j].to_be();
        //eprintln!("{map:x}");
        while map != 0 {
            let i = map.trailing_zeros();
            hash ^= (key32[j].to_be() << (31 - i))
                | (u64::from(key32[j + 1].to_be()) >> (i + 1)) as u32;
            // remove the least significant bit
            map &= map - 1;
        }
    }
    hash
}

/// Toeplitz (RSS) hash algorithm, optimized for 32-bits aligned data and *big-endian* key
pub fn toeplitz_hash_aligned32_v2(key: &[u32], data: &[u8]) -> u32 {
    let (_prefix, data32, _suffix) = unsafe { data.align_to::<u32>() };
    debug_assert_eq!(_prefix.len(), 0, "data is not aligned properly");
    debug_assert_eq!(_suffix.len(), 0, "input data length not a multiple of 4");
    debug_assert!(data32.len() < key.len());
    let mut hash: u32 = 0;
    for j in 0..data32.len() {
        let mut map = data32[j].to_be();
        //eprintln!("{map:x}");
        while map != 0 {
            let i = map.trailing_zeros();
            hash ^= (key[j] << (31 - i)) | (u64::from(key[j + 1]) >> (i + 1)) as u32;
            // remove the least significant bit
            map &= map - 1;
        }
    }
    hash
}

/// Toeplitz (RSS) hash algorithm, optimized for 32-bits *big-endian* data and *big-endian* key
pub fn toeplitz_hash_u32be(key: &[u32], data: &[u32]) -> u32 {
    let mut hash: u32 = 0;
    for j in 0..data.len() {
        let mut map = data[j];
        //eprintln!("{map:x}");
        while map != 0 {
            let i = map.trailing_zeros();
            hash ^= (key[j] << (31 - i)) | (u64::from(key[j + 1]) >> (i + 1)) as u32;
            // remove the least significant bit
            map &= map - 1;
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    #[test]
    fn toeplitz_hash_test() {
        const DATA1: &[u8] = &[66, 9, 149, 187, 161, 142, 100, 80, 10, 234, 6, 230];
        let res = toeplitz_hash(&DEFAULT_KEY, DATA1);
        assert_eq!(res, 0x51cc_c178);
        const DATA2: &[u8] = &[199, 92, 111, 2, 65, 69, 140, 83, 55, 150, 18, 131];
        let res = toeplitz_hash(&DEFAULT_KEY, DATA2);
        assert_eq!(res, 0xc626_b0ea);
    }

    // test vectors inspired from https://github.com/sarub0b0/toeplitz-hash/blob/master/toeplitz_hash.cc
    #[derive(Debug)]
    struct TestVector {
        src_addr: IpAddr,
        dst_addr: IpAddr,
        src_port: u16,
        dst_port: u16,
        with_tcp_hash: u32,
        without_tcp_hash: u32,
    }

    fn create_test_vectors() -> Vec<TestVector> {
        let mut v = Vec::new();

        const TESTV4_1: TestVector = TestVector {
            src_addr: IpAddr::V4(Ipv4Addr::new(66, 9, 149, 187)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(161, 142, 100, 80)),
            src_port: 2794,
            dst_port: 1766,
            with_tcp_hash: 0x51c_cc178,
            without_tcp_hash: 0x323_e8fc2,
        };
        v.push(TESTV4_1);

        let testv6_1: TestVector = TestVector {
            src_addr: IpAddr::V6(Ipv6Addr::from_str("3ffe:2501:200:1fff::7").unwrap()),
            dst_addr: IpAddr::V6(Ipv6Addr::from_str("3ffe:2501:200:3::1").unwrap()),
            src_port: 2794,
            dst_port: 1766,
            with_tcp_hash: 0x4020_7d3d,
            without_tcp_hash: 0x2cc18cd5,
        };
        v.push(testv6_1);

        v
    }

    #[rustfmt::skip]
    fn prepare_buffer(src_addr: IpAddr, dst_addr: IpAddr, src_port: u16, dst_port: u16) -> ([u8;40], usize) {
        #[repr(C, align(4))]
        struct AlignedBuffer(pub [u8; 40]);

        let mut aligned = AlignedBuffer([0; 40]);
        let buf = &mut aligned.0;
        let sz = match src_addr {
            IpAddr::V4(v4) => { buf[..4].copy_from_slice(&v4.octets()); 4 },
            IpAddr::V6(v6) => { buf[..16].copy_from_slice(&v6.octets()); 16 },
        };
        let sz = match dst_addr {
            IpAddr::V4(v4) => { buf[4..8].copy_from_slice(&v4.octets()); sz+4 },
            IpAddr::V6(v6) => { buf[16..32].copy_from_slice(&v6.octets()); sz+16 },
        };
        buf[sz    ] = ((src_port & 0xff00) >> 8) as u8;
        buf[sz + 1] = (src_port & 0x00ff) as u8;
        buf[sz + 2] = ((dst_port & 0xff00) >> 8) as u8;
        buf[sz + 3] = (dst_port & 0x00ff) as u8;

        (aligned.0, sz + 4)
    }

    #[test]
    fn toeplitz_test_vectors() {
        let test_vectors = create_test_vectors();
        for v in &test_vectors {
            // println!("{:?}", v);
            let (buf, sz) = prepare_buffer(v.src_addr, v.dst_addr, v.src_port, v.dst_port);
            let without_tcp_hash = toeplitz_hash(&DEFAULT_KEY, &buf[..sz - 4]);
            // println!("{:02x?}", without_tcp_hash);
            assert_eq!(without_tcp_hash, v.without_tcp_hash);

            let with_tcp_hash = toeplitz_hash(&DEFAULT_KEY, &buf[..sz]);
            // println!("{:02x?}", with_tcp_hash);
            assert_eq!(with_tcp_hash, v.with_tcp_hash);
        }
    }

    // Test hash symmetry
    // Note that we use a different key for hashes (default one creates symmetric hashes for
    // IPv4/IPv6 only, but not when adding ports
    #[test]
    fn toeplitz_hash_symmetry() {
        let test_vectors = create_test_vectors();
        for v in &test_vectors {
            let v_sym = TestVector {
                dst_addr: v.dst_addr,
                src_addr: v.src_addr,
                src_port: v.dst_port,
                dst_port: v.src_port,
                with_tcp_hash: v.with_tcp_hash,
                without_tcp_hash: v.without_tcp_hash,
            };

            let (buf, sz) = prepare_buffer(v.src_addr, v.dst_addr, v.src_port, v.dst_port);
            let without_tcp_hash = toeplitz_hash(&SYMMETRIC_KEY, &buf[..sz - 4]);
            let (buf2, sz2) = prepare_buffer(
                v_sym.src_addr,
                v_sym.dst_addr,
                v_sym.src_port,
                v_sym.dst_port,
            );
            let without_tcp_hash_sym = toeplitz_hash(&SYMMETRIC_KEY, &buf2[..sz2 - 4]);
            // println!("{:02x?}", without_tcp_hash);
            assert_eq!(
                without_tcp_hash, without_tcp_hash_sym,
                "Symmetry without ports"
            );

            let with_tcp_hash = toeplitz_hash(&SYMMETRIC_KEY, &buf[..sz]);
            let with_tcp_hash_sym = toeplitz_hash(&SYMMETRIC_KEY, &buf2[..sz2]);
            // println!("{:02x?}", with_tcp_hash);
            assert_eq!(with_tcp_hash, with_tcp_hash_sym, "Symmetry with ports");
        }
    }

    #[test]
    fn toeplitz_test_optim() {
        let test_vectors = create_test_vectors();
        for v in &test_vectors {
            // println!("{:?}", v);
            let (buf, sz) = prepare_buffer(v.src_addr, v.dst_addr, v.src_port, v.dst_port);

            let unopt = toeplitz_hash(&DEFAULT_KEY, &buf[..sz - 4]);
            // println!("{:02x?}", without_tcp_hash);
            assert_eq!(unopt, v.without_tcp_hash);

            let opt = toeplitz_hash_aligned32(&DEFAULT_KEY, &buf[..sz - 4]);
            // println!("{:02x?}", with_tcp_hash);
            assert_eq!(unopt, opt);

            let opt = toeplitz_hash_aligned32_v2(DEFAULT_KEY_U32BE, &buf[..sz - 4]);
            // println!("{:02x?}", with_tcp_hash);
            assert_eq!(unopt, opt);
        }
    }
}
