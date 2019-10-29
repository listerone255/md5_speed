extern crate md5_speed;

fn main() {
    let mut inp = [0; 65536];

    for i in 0..16384 {
        let oup = md5_speed::md5(&inp[..]);
    }

    for i in 0..16384 {
        use md5::Digest;
        let mut h = md5::Md5::new();
        h.input(&inp[..]);
        h.result();
    }
}
