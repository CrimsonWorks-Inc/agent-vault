//! Small helpers the JS gets from its runtime: `Date.now()`,
//! `new Date(ms).toISOString()`, `Date.parse`, and `String(number)`.
//!
//! `Date.parse` is ported for the forms the vault stores and accepts: ISO 8601
//! dates and date-times (`T`, `t` or a space between), with `Z` or a numeric
//! offset, plus V8's legacy `YYYY/MM/DD` and `YYYY-M-D`. One deliberate
//! difference: a date-time with no offset is read as UTC, where V8 reads it
//! as local time. Every date the vault writes carries `Z`.

#[cfg(test)]
thread_local! {
    /// A fixed clock for this test thread (the JS tests replace `Date.now`).
    static FIXED_NOW: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
}

/// Run `f` with the clock at `ms` on this thread. Test-only.
#[cfg(test)]
pub(crate) fn at<T>(ms: i64, f: impl FnOnce() -> T) -> T {
    let before = FIXED_NOW.with(|c| c.replace(Some(ms)));
    let out = f();
    FIXED_NOW.with(|c| c.set(before));
    out
}

/// Milliseconds since the epoch, now.
pub(crate) fn now_ms() -> i64 {
    #[cfg(test)]
    if let Some(t) = FIXED_NOW.with(|c| c.get()) {
        return t;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `new Date(ms).toISOString()`.
pub(crate) fn iso(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s, milli) = (
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000,
    );
    if (0..=9999).contains(&y) {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{milli:03}Z")
    } else {
        let sign = if y < 0 { '-' } else { '+' };
        format!(
            "{sign}{:06}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{milli:03}Z",
            y.abs()
        )
    }
}

/// `iso(now_ms())`.
pub(crate) fn now_iso() -> String {
    iso(now_ms())
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) to days since 1970-01-01. Day may overflow its month,
/// as V8 lets it (`2026-02-30` is March 2).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `Date.parse(s)`, or `None` where it is NaN. See the module note.
pub(crate) fn parse_ms(s: &str) -> Option<i64> {
    let b = s.trim().as_bytes();
    let mut i = 0;
    let digits = |i: &mut usize, min: usize, max: usize| -> Option<i64> {
        let start = *i;
        while *i < b.len() && *i - start < max && b[*i].is_ascii_digit() {
            *i += 1;
        }
        if *i - start < min {
            return None;
        }
        std::str::from_utf8(&b[start..*i]).ok()?.parse().ok()
    };
    // Year: four digits, or a sign and six.
    let year = match b.first()? {
        b'+' | b'-' => {
            let neg = b[0] == b'-';
            i = 1;
            let y = digits(&mut i, 6, 6)?;
            if i != 7 {
                return None;
            }
            if neg {
                -y
            } else {
                y
            }
        }
        _ => {
            let y = digits(&mut i, 4, 4)?;
            if i != 4 {
                return None;
            }
            y
        }
    };
    let (mut month, mut day) = (1, 1);
    let legacy_sep = b.get(i).copied();
    if matches!(legacy_sep, Some(b'-') | Some(b'/')) {
        let sep = b[i];
        i += 1;
        month = digits(&mut i, 1, 2)?;
        if b.get(i) == Some(&sep) {
            i += 1;
            day = digits(&mut i, 1, 2)?;
        }
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (mut h, mut mi, mut sec, mut ms) = (0, 0, 0, 0);
    let mut offset_min: i64 = 0;
    if i < b.len() {
        if !matches!(b[i], b'T' | b't' | b' ') {
            return None;
        }
        i += 1;
        h = digits(&mut i, 2, 2)?;
        if b.get(i) != Some(&b':') {
            return None;
        }
        i += 1;
        mi = digits(&mut i, 2, 2)?;
        if b.get(i) == Some(&b':') {
            i += 1;
            sec = digits(&mut i, 2, 2)?;
            if b.get(i) == Some(&b'.') {
                i += 1;
                let start = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                if i == start {
                    return None;
                }
                let frac = std::str::from_utf8(&b[start..i]).ok()?;
                let first3: String = frac.chars().chain("00".chars()).take(3).collect();
                ms = first3.parse().ok()?;
            }
        }
        match b.get(i) {
            None => {}
            Some(b'Z') | Some(b'z') => i += 1,
            Some(b'+') | Some(b'-') => {
                let neg = b[i] == b'-';
                i += 1;
                let oh = digits(&mut i, 2, 2)?;
                if b.get(i) == Some(&b':') {
                    i += 1;
                }
                let om = digits(&mut i, 2, 2)?;
                if oh > 23 || om > 59 {
                    return None;
                }
                offset_min = (oh * 60 + om) * if neg { -1 } else { 1 };
            }
            _ => return None,
        }
        if i != b.len() {
            return None;
        }
        let valid = (h < 24 && mi < 60 && sec < 60) || (h == 24 && mi == 0 && sec == 0 && ms == 0);
        if !valid {
            return None;
        }
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86_400_000 + h * 3_600_000 + mi * 60_000 + sec * 1000 + ms - offset_min * 60_000)
}

/// `isoOrUndefined`: an ISO date normalised, or `None` when `s` is not one.
pub(crate) fn iso_normalized(s: &str) -> Option<String> {
    parse_ms(s).map(iso)
}

/// `String(n)` for a finite number, as JS prints it.
pub(crate) fn js_number_string(n: f64) -> String {
    if n == 0.0 {
        return "0".into();
    }
    if n.fract() == 0.0 && n.abs() < 1e21 {
        return format!("{n:.0}");
    }
    let abs = n.abs();
    if (1e-6..1e21).contains(&abs) {
        return format!("{n}");
    }
    // Exponent form: shortest digits, then JS's `e+N` / `e-N`.
    let s = format!("{n:e}");
    match s.split_once('e') {
        Some((m, e)) if !e.starts_with('-') => format!("{m}e+{e}"),
        Some((m, e)) => format!("{m}e{e}"),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_matches_to_iso_string() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_767_261_600_123), "2026-01-01T10:00:00.123Z");
        assert_eq!(iso(-1), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn parse_matches_v8_for_iso_forms() {
        let cases: &[(&str, Option<i64>)] = &[
            ("2026-02-30", Some(1_772_409_600_000)),
            ("2026-02-29", Some(1_772_323_200_000)),
            ("2026-13-01", None),
            ("2026-01-01T24:00:00Z", Some(1_767_312_000_000)),
            ("2026-01-01T10:00Z", Some(1_767_261_600_000)),
            ("2026-01-01T10:00:00.123456Z", Some(1_767_261_600_123)),
            ("2026-01-01T10:00:00+05:30", Some(1_767_241_800_000)),
            ("2026-01-01T10:00:00+0530", Some(1_767_241_800_000)),
            ("2026", Some(1_767_225_600_000)),
            ("2026-01", Some(1_767_225_600_000)),
            ("2026-01-01 10:00:00Z", Some(1_767_261_600_000)),
            ("not a date", None),
            ("+002026-01-01T00:00:00Z", Some(1_767_225_600_000)),
            ("2026-01-01T10:00:60Z", None),
            ("2026-01-01t10:00:00z", Some(1_767_261_600_000)),
            ("", None),
        ];
        for (s, want) in cases {
            assert_eq!(parse_ms(s), *want, "{s}");
        }
    }

    #[test]
    fn round_trip() {
        for ms in [0, 1, 1_767_261_600_123, 4_102_444_800_000] {
            assert_eq!(parse_ms(&iso(ms)), Some(ms));
        }
    }

    #[test]
    fn numbers_print_like_js() {
        assert_eq!(js_number_string(1.5), "1.5");
        assert_eq!(js_number_string(3.0), "3");
        assert_eq!(js_number_string(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(js_number_string(1e21), "1e+21");
        assert_eq!(js_number_string(1.5e-7), "1.5e-7");
    }
}
