extern crate md5;
extern crate md5_speed;

use criterion::*;

fn benchmark_comparison(c: &mut Criterion) {
    let size = 65536;
    let buf = (0..=255).cycle().take(size).collect::<Vec<u8>>();

    let mut group = c.benchmark_group("MD5 comparison");
    group.warm_up_time(std::time::Duration::new(1, 0));
    group.measurement_time(std::time::Duration::new(3, 0));
    group.throughput(Throughput::Bytes(size as u64));
    group.bench_function("mine", |b| b.iter(|| crate::md5_speed::md5(&buf)));
    group.bench_function("crate", |b| {
        b.iter(|| {
            use md5::Digest;
            let mut h = md5::Md5::new();
            h.input(&buf);
            h.result()
        })
    });
    group.finish();
}

criterion_group!(benches, benchmark_comparison);
criterion_main!(benches);
