//! Timestamp helpers.
//!
//! The workspace formats its own RFC 3339 strings so that the shared types crate
//! stays dependency-free; the conversion follows Howard Hinnant's `civil_from_days`
//! algorithm and is covered by round-trip tests.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A UTC timestamp with millisecond resolution.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct UtcStamp {
    millis: u64,
}

impl UtcStamp {
    /// Builds a stamp from milliseconds since the Unix epoch.
    pub const fn from_millis(millis: u64) -> Self {
        Self { millis }
    }

    /// The current time.
    pub fn now() -> Self {
        utc_now()
    }

    /// Milliseconds since the Unix epoch.
    pub const fn millis(&self) -> u64 {
        self.millis
    }

    /// Whole seconds since the Unix epoch.
    pub const fn secs(&self) -> u64 {
        self.millis / 1000
    }

    /// Milliseconds elapsed since this stamp, saturating at zero.
    pub fn elapsed_millis(&self) -> u64 {
        utc_now().millis.saturating_sub(self.millis)
    }

    /// Renders the stamp as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub fn to_rfc3339(&self) -> String {
        format_rfc3339(self.millis)
    }
}

impl fmt::Display for UtcStamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// The current UTC time as a [`UtcStamp`].
pub fn utc_now() -> UtcStamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u64::MAX as u128) as u64;
    UtcStamp::from_millis(millis)
}

/// Formats milliseconds since the epoch as an RFC 3339 UTC timestamp.
pub fn format_rfc3339(millis: u64) -> String {
    let (year, month, day) = civil_from_days((millis / 86_400_000) as i64);
    let remainder = millis % 86_400_000;
    let hour = remainder / 3_600_000;
    let minute = (remainder % 3_600_000) / 60_000;
    let second = (remainder % 60_000) / 1000;
    let milli = remainder % 1000;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milli:03}Z")
}

/// Formats a number of seconds as `1d 02:03:04`.
pub fn format_uptime(total_seconds: u64) -> String {
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    if days > 0 {
        format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

/// Days since 1970-01-01 to (year, month, day) in the civil calendar.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn formats_known_timestamps() {
        // 2024-02-29T23:59:59.500Z (a leap day, just before midnight)
        let millis: u64 = 1_709_251_199_500;
        assert_eq!(format_rfc3339(millis), "2024-02-29T23:59:59.500Z");
        // 2000-01-01T00:00:00.000Z
        assert_eq!(format_rfc3339(946_684_800_000), "2000-01-01T00:00:00.000Z");
        // 2038-01-19T03:14:07.000Z - the 32 bit overflow point
        assert_eq!(
            format_rfc3339(2_147_483_647_000),
            "2038-01-19T03:14:07.000Z"
        );
    }

    #[test]
    fn every_day_of_a_four_year_cycle_maps_back() {
        // Walk two full leap cycles and check the day counter is consistent.
        let mut days = 0i64;
        let mut expected = days_since_civil(1970, 1, 1);
        for _ in 0..(365 * 8 + 2) {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_since_civil(year, month, day), expected);
            days += 1;
            expected += 1;
        }
    }

    #[test]
    fn uptime_is_human_readable() {
        assert_eq!(format_uptime(59), "00:00:59");
        assert_eq!(format_uptime(3661), "01:01:01");
        assert_eq!(format_uptime(90_061), "1d 01:01:01");
    }

    #[test]
    fn stamps_measure_elapsed_time() {
        let stamp = UtcStamp::from_millis(utc_now().millis().saturating_sub(1500));
        assert!(stamp.elapsed_millis() >= 1500);
    }

    /// Inverse of [`civil_from_days`], used only by the tests above.
    fn days_since_civil(year: i64, month: u32, day: u32) -> i64 {
        let y = if month <= 2 { year - 1 } else { year };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as u64;
        let m = month as u64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as u64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe as i64 - 719_468
    }
}
