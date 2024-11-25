/// Maximum key size used throughout.  It's OK for hardware to use only the
/// first 16 bytes, which is all that's required for IPv4.
pub const RSS_KEYSIZE: usize = 40;

// original Microsoft's key
#[rustfmt::skip]
pub const DEFAULT_KEY : &[u8] = &[
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
];

// key from http://www.ndsl.kaist.edu/~shinae/papers/TR-symRSS.pdf
//
// Let’s assume we have a frame IP source: 1.1.1.1, IP destination: 2.2.2.2 and UDP port 22 to udp
// port 55. This means that the input for the hash function of the 4 tuples will be:
// [1.1.1.1][2.2.2.2][22][55] and for the opposite direction: [2.2.2.2][1.1.1.1][55][22]. To
// support the same hash value for these two inputs, the first 32bit of the key need to be
// identical to the second 32bit, and the 16bit afterwards should be identical to the next 16bit.
#[rustfmt::skip]
pub const SYMMETRIC_KEY : &[u8] = &[
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
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
        let res = toeplitz_hash(DEFAULT_KEY, DATA1);
        assert_eq!(res, 0x51cc_c178);
        const DATA2: &[u8] = &[199, 92, 111, 2, 65, 69, 140, 83, 55, 150, 18, 131];
        let res = toeplitz_hash(DEFAULT_KEY, DATA2);
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
        let mut buf = [0u8; 40];
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

        (buf, sz + 4)
    }

    #[test]
    fn toeplitz_test_vectors() {
        let test_vectors = create_test_vectors();
        for v in &test_vectors {
            // println!("{:?}", v);
            let (buf, sz) = prepare_buffer(v.src_addr, v.dst_addr, v.src_port, v.dst_port);
            let without_tcp_hash = toeplitz_hash(DEFAULT_KEY, &buf[..sz - 4]);
            // println!("{:02x?}", without_tcp_hash);
            assert_eq!(without_tcp_hash, v.without_tcp_hash);

            let with_tcp_hash = toeplitz_hash(DEFAULT_KEY, &buf[..sz]);
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
            let without_tcp_hash = toeplitz_hash(SYMMETRIC_KEY, &buf[..sz - 4]);
            let (buf2, sz2) = prepare_buffer(
                v_sym.src_addr,
                v_sym.dst_addr,
                v_sym.src_port,
                v_sym.dst_port,
            );
            let without_tcp_hash_sym = toeplitz_hash(SYMMETRIC_KEY, &buf2[..sz2 - 4]);
            // println!("{:02x?}", without_tcp_hash);
            assert_eq!(
                without_tcp_hash, without_tcp_hash_sym,
                "Symmetry without ports"
            );

            let with_tcp_hash = toeplitz_hash(SYMMETRIC_KEY, &buf[..sz]);
            let with_tcp_hash_sym = toeplitz_hash(SYMMETRIC_KEY, &buf2[..sz2]);
            // println!("{:02x?}", with_tcp_hash);
            assert_eq!(with_tcp_hash, with_tcp_hash_sym, "Symmetry with ports");
        }
    }
}
