use criterion::{criterion_group, criterion_main, Criterion};
use veilkit_core::Engine;

fn mixed_text(target_bytes: usize) -> String {
    let chunk = "Hi team, please call 415-555-0199 or email ops@example.com before Friday. \
Patient MRN: 00912345, DOB: 04/12/1985, NPI 1234567893. Card on file 4111 1111 1111 1111 exp 09/27. \
Routing number 021000021, account number 000123456789. Deploy token ghp_abcdefghijklmnopqrstuvwxyz0123456789 \
and key AKIAIOSFODNN7EXAMPLE. Visit https://mychart.example.org/feed?mrn=12345 for results. \
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore. ";
    let mut s = String::new();
    while s.len() < target_bytes {
        s.push_str(chunk);
    }
    s
}

fn bench_scan(c: &mut Criterion) {
    let engine = Engine::all_packs().expect("engine");
    let text = mixed_text(10 * 1024);
    c.bench_function("scan_10kb_all_packs", |b| b.iter(|| engine.scan(&text)));
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
