//! CSV pipeline benchmarks (no gpg encryption).
//!
//! gpg encryption is an external subprocess — there's nothing of ours
//! to measure in it. What we benchmark here is exactly what bounds the
//! tool's throughput at a given parallelism: CSV parsing, Title
//! sanitization, and plaintext-entry assembly.
//!
//! To run:
//!     make gen-1k        # once — create the fixture
//!     cargo bench        # or `make bench`

use std::io::Cursor;
use std::path::PathBuf;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rspassimpt::sanitize::{RawRow, build_entry, sanitize_path};
use std::hint::black_box;

// ---------- micro: sanitize_path ----------

fn bench_sanitize(c: &mut Criterion) {
    let titles = [
        "secure.granite.xyz (apollo123@protonmail.com) #42",
        "Документы/Основной #1000",
        "  .. / leading-dots ..  / weird ",
        "../../etc/passwd",
        "Гараж #50",
        "a/b/c/d/e/f/g/h",
        "single",
    ];
    let mut group = c.benchmark_group("sanitize_path");
    group.throughput(Throughput::Elements(titles.len() as u64));
    group.bench_function("mixed", |b| {
        b.iter(|| {
            for t in &titles {
                black_box(sanitize_path(black_box(t)));
            }
        })
    });
    group.finish();
}

// ---------- micro: build_entry ----------

fn make_synthetic_row(i: usize) -> RawRow {
    RawRow {
        title: format!("portal.obsidian{i}.cloud (atlas{i}@protonmail.com) #{i}"),
        url: format!("https://portal.obsidian{i}.cloud/"),
        username: format!("atlas{i}@protonmail.com"),
        password: "Tk9!aZx@qPm#vR8sL2$wY7nE4cBjU0".into(),
        notes: if i.is_multiple_of(50) {
            "Срок продлевается автоматически\nЗапасной набор в сейфе".into()
        } else {
            String::new()
        },
        otpauth: if i.is_multiple_of(200) {
            "otpauth://totp/example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=t".into()
        } else {
            String::new()
        },
    }
}

fn bench_build_entry(c: &mut Criterion) {
    let rows: Vec<RawRow> = (0..1024).map(make_synthetic_row).collect();
    let mut group = c.benchmark_group("build_entry");
    group.throughput(Throughput::Elements(rows.len() as u64));
    group.bench_function("1024_rows", |b| {
        b.iter(|| {
            for r in &rows {
                let entry = build_entry(black_box(r));
                black_box(entry);
            }
        })
    });
    group.finish();
}

// ---------- macro: full CSV pipeline (parse + sanitize + build) ----------

fn fixture_path(size: &str) -> PathBuf {
    PathBuf::from(format!("tests/fixtures/passwd_{size}.csv"))
}

fn bench_pipeline_csv(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_csv");
    for size in ["1k", "100k"] {
        let path = fixture_path(size);
        if !path.exists() {
            eprintln!(
                "skipping pipeline_csv/{size}: {} not found (run `make gen-{size}`)",
                path.display()
            );
            continue;
        }
        let bytes = std::fs::read(&path).expect("read fixture");
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("parse_sanitize_build", size),
            &bytes,
            |b, data| {
                b.iter(|| {
                    let mut reader = csv::ReaderBuilder::new()
                        .has_headers(true)
                        .from_reader(Cursor::new(data));
                    let mut n = 0u64;
                    for r in reader.deserialize::<RawRow>() {
                        let row = match r {
                            Ok(r) => r,
                            Err(_) => continue,
                        };
                        let title = sanitize_path(&row.title);
                        if title.is_empty() || row.password.trim().is_empty() {
                            continue;
                        }
                        let entry = build_entry(&row);
                        black_box(entry);
                        n += 1;
                    }
                    black_box(n);
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sanitize,
    bench_build_entry,
    bench_pipeline_csv
);
criterion_main!(benches);
