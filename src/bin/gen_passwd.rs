//! Synthetic CSV generator in the macOS Passwords export format.
//!
//! Uses xorshift64* PRNG (no `rand` dependency — keeps build fast and the
//! dependency surface minimal). Quality is plenty for the use case: this
//! is bench fixture data, not cryptography.
//!
//! The pools of names, domains, phones and notes are intentionally disjoint
//! from any real user export — no `gmail.com`/`+7...`/names from the
//! user's own data.

use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "gen_passwd",
    about = "Synthetic macOS Passwords CSV generator for rspassimpt benchmarks"
)]
struct Args {
    /// Number of rows to generate
    rows: u64,
    /// Output CSV path
    output: PathBuf,
    /// RNG seed (deterministic output for the same N+seed)
    #[arg(long, default_value_t = 0x5e_ed_ca_fe_d0_d0_be_ef)]
    seed: u64,
}

// ============================================================================
// xorshift64* — tiny deterministic PRNG.
// ============================================================================

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // 0 is a fixed point for xorshift; substitute a non-zero constant.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Half-open range `[0, hi)`. A slight modulo bias is acceptable here.
    #[inline]
    fn below(&mut self, hi: u64) -> u64 {
        self.next_u64() % hi
    }

    #[inline]
    fn range_u32(&mut self, lo: u32, hi_inclusive: u32) -> u32 {
        let span = (hi_inclusive - lo + 1) as u64;
        lo + (self.below(span) as u32)
    }

    #[inline]
    fn bool(&mut self, p: f64) -> bool {
        // [0, 1)
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64) < p
    }

    #[inline]
    fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        &slice[self.below(slice.len() as u64) as usize]
    }
}

// ============================================================================
// Data pools — intentionally disjoint from any real user export.
// ============================================================================

// Minerals / gemstones / Greek mythology.
const WORDS: &[&str] = &[
    "granite",
    "basalt",
    "obsidian",
    "marble",
    "slate",
    "schist",
    "gneiss",
    "pumice",
    "dolomite",
    "shale",
    "gabbro",
    "andesite",
    "rhyolite",
    "quarzite",
    "amber",
    "opal",
    "beryl",
    "topaz",
    "garnet",
    "peridot",
    "citrine",
    "onyx",
    "agate",
    "tourmaline",
    "lapis",
    "malachite",
    "jasper",
    "spinel",
    "zircon",
    "atlas",
    "hermes",
    "apollo",
    "artemis",
    "athena",
    "demeter",
    "hestia",
    "hephaestus",
    "dionysus",
    "persephone",
    "selene",
    "helios",
    "iris",
    "hekate",
];

const TLDS: &[&str] = &[
    "xyz", "sh", "info", "biz", "store", "online", "site", "cloud", "services", "page", "blog",
    "news", "fyi", "link", "today", "shop", "studio", "agency",
];

const SUBDOMAINS: &[&str] = &[
    "",
    "",
    "",
    "portal.",
    "secure.",
    "my.",
    "id.",
    "dashboard.",
    "login.",
    "account.",
    "console.",
];

const EMAIL_DOMAINS: &[&str] = &[
    "protonmail.com",
    "fastmail.com",
    "tutanota.com",
    "posteo.de",
    "mailbox.org",
    "gmx.de",
    "zoho.com",
    "hey.com",
    "kolab.com",
    "disroot.org",
    "riseup.net",
    "hushmail.com",
    "runbox.com",
    "mailfence.com",
    "tutamail.com",
    "soverin.net",
];

const RU_TITLES: &[&str] = &[
    "Документы",
    "Финансы",
    "Здоровье",
    "Транспорт",
    "Развлечения",
    "Покупки",
    "Образование",
    "Связь",
    "Жильё",
    "Гараж",
    "Хобби",
    "Спорт",
    "Путешествия",
    "Питомцы",
    "Семья",
];

const RU_LEAVES: &[&str] = &[
    "Основной",
    "Доп. кабинет",
    "Запасной",
    "Семейный",
    "Личный",
    "Корпоративный",
    "Долгосрочный",
    "Архив",
    "Активный",
    "Завершённый",
    "Тестовый",
    "Демо",
    "Резервный",
];

const RU_NOTES: &[&str] = &[
    "Получено в офисе",
    "Восстановление через бумажный код",
    "Действует до конца квартала",
    "Хранить только локально",
    "Совместный доступ с коллегами",
    "Срок продлевается автоматически",
    "Привязан к корпоративному устройству",
    "Запасной набор в сейфе",
    // ~70% empty — matches the real-world export distribution.
    "",
    "",
    "",
    "",
    "",
    "",
    "",
];

/// Country code and the number of subscriber digits (excluding the country code).
/// +7 (Russia) is intentionally omitted — that's the code from the original sample.
const COUNTRY_CODES: &[(&str, u8)] = &[
    ("1", 10),  // US/Canada
    ("44", 10), // UK
    ("49", 11), // Germany
    ("33", 9),  // France
    ("39", 10), // Italy
    ("81", 10), // Japan
    ("82", 10), // South Korea
    ("86", 11), // China
    ("90", 10), // Turkey
    ("371", 8), // Latvia
    ("372", 8), // Estonia
    ("420", 9), // Czechia
    ("48", 9),  // Poland
    ("31", 9),  // Netherlands
    ("46", 9),  // Sweden
    ("47", 8),  // Norway
    ("358", 9), // Finland
    ("351", 9), // Portugal
    ("34", 9),  // Spain
    ("30", 10), // Greece
    ("353", 9), // Ireland
    ("356", 8), // Malta
    ("357", 8), // Cyprus
    ("370", 8), // Lithuania
    ("380", 9), // Ukraine
    ("995", 9), // Georgia
];

const PASSWORD_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// ============================================================================
// Field generation.
// ============================================================================

fn password(rng: &mut Rng) -> String {
    let n = rng.range_u32(14, 32) as usize;
    let mut s = String::with_capacity(n);
    for _ in 0..n {
        let i = rng.below(PASSWORD_ALPHABET.len() as u64) as usize;
        s.push(PASSWORD_ALPHABET[i] as char);
    }
    s
}

fn hostname(rng: &mut Rng) -> String {
    let a = rng.pick(WORDS);
    let b = rng.pick(WORDS);
    let sub = rng.pick(SUBDOMAINS);
    let tld = rng.pick(TLDS);
    format!("{sub}{a}{b}.{tld}")
}

/// Email with a unique numeric suffix and a rotating domain — at 1M rows
/// the collision count is negligible.
fn email(rng: &mut Rng) -> String {
    let base = rng.pick(WORDS);
    let n = rng.range_u32(10, 99_999);
    let domain = rng.pick(EMAIL_DOMAINS);
    format!("{base}{n}@{domain}")
}

/// International phone in `+CCDDDDDDDDD` format. The country code is
/// chosen randomly from the pool; the first national digit is never zero.
fn phone(rng: &mut Rng) -> String {
    let (cc, digits) = rng.pick(COUNTRY_CODES);
    let mut s = String::with_capacity(cc.len() + *digits as usize + 1);
    s.push('+');
    s.push_str(cc);
    s.push(char::from_digit(rng.range_u32(1, 9), 10).unwrap());
    for _ in 1..*digits {
        s.push(char::from_digit(rng.range_u32(0, 9), 10).unwrap());
    }
    s
}

fn username(rng: &mut Rng) -> String {
    // 70% email, 30% phone — balance matches typical real CSV exports.
    if rng.bool(0.7) {
        email(rng)
    } else {
        phone(rng)
    }
}

fn notes(rng: &mut Rng) -> String {
    if rng.bool(0.01) {
        // ~1% — multi-line notes with commas/quotes: exercise the CSV
        // escaping path and the pipeline's handling of multi-line fields.
        "Строка 1\nСтрока 2, с запятой и кавычкой \"\nСтрока 3".to_string()
    } else {
        rng.pick(RU_NOTES).to_string()
    }
}

fn otpauth(rng: &mut Rng, label: &str) -> String {
    if !rng.bool(0.005) {
        return String::new();
    }
    let mut secret = String::with_capacity(32);
    for _ in 0..32 {
        let i = rng.below(BASE32_ALPHABET.len() as u64) as usize;
        secret.push(BASE32_ALPHABET[i] as char);
    }
    format!("otpauth://totp/{label}?secret={secret}&issuer=test")
}

fn make_row(i: u64, rng: &mut Rng) -> [String; 6] {
    let pick = rng.below(100);

    let (title, url) = if pick < 8 {
        // ~8% — hierarchical Cyrillic title (produces pass sub-directories).
        let t = rng.pick(RU_TITLES);
        let l = rng.pick(RU_LEAVES);
        (format!("{t}/{l} #{i}"), String::new())
    } else if pick < 14 {
        // ~6% — flat Cyrillic title.
        let t = rng.pick(RU_TITLES);
        (format!("{t} #{i}"), String::new())
    } else {
        // ~86% — regular `host (user) #N`.
        let h = hostname(rng);
        let u = username(rng);
        (format!("{h} ({u}) #{i}"), format!("https://{h}/"))
    };

    let user = username(rng);
    let password = password(rng);
    let notes_v = notes(rng);
    let otpauth_v = otpauth(rng, &title);

    [title, url, user, password, notes_v, otpauth_v]
}

// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();
    let mut rng = Rng::new(args.seed ^ args.rows);

    let file =
        File::create(&args.output).with_context(|| format!("create {}", args.output.display()))?;
    let writer = BufWriter::with_capacity(1 << 20, file);
    let mut wtr = csv::WriterBuilder::new()
        .quote_style(csv::QuoteStyle::Necessary)
        .from_writer(writer);

    wtr.write_record(["Title", "URL", "Username", "Password", "Notes", "OTPAuth"])?;
    for i in 1..=args.rows {
        let row = make_row(i, &mut rng);
        wtr.write_record(&row)?;
    }
    wtr.flush()?;

    let size_mb = std::fs::metadata(&args.output)?.len() as f64 / (1024.0 * 1024.0);
    eprintln!(
        "{}: {} rows, {:.2} MiB",
        args.output.display(),
        args.rows,
        size_mb
    );
    Ok(())
}
