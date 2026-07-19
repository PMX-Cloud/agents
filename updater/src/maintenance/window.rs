use anyhow::{bail, Context, Result};
use chrono::{DateTime, Datelike, NaiveTime, TimeZone, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowSet {
    pub windows: Vec<WindowSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowSpec {
    pub days: Vec<String>,
    pub start: String,
    pub end: String,
    pub tz: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveWindow {
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaintenanceStatus {
    pub active: bool,
    pub window: Option<ActiveWindow>,
}

pub fn write_cache(path: &str, set: &WindowSet) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).with_context(|| format!("create cache dir for {}", path))?;
    }
    let payload = serde_json::to_vec_pretty(set).context("serialize maintenance windows")?;
    fs::write(path, payload).with_context(|| format!("write maintenance cache {}", path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .with_context(|| format!("chmod maintenance cache {}", path))?;
    }
    Ok(())
}

pub fn read_cache(path: &str) -> Result<WindowSet> {
    let raw = fs::read(path).with_context(|| format!("read maintenance cache {}", path))?;
    serde_json::from_slice(&raw).context("parse maintenance cache")
}

pub fn is_now(set: &WindowSet, now: DateTime<Utc>) -> Result<MaintenanceStatus> {
    for (index, window) in set.windows.iter().enumerate() {
        if window_active(window, now)? {
            return Ok(MaintenanceStatus {
                active: true,
                window: Some(ActiveWindow {
                    identifier: format!("window-{}", index),
                }),
            });
        }
    }
    Ok(MaintenanceStatus {
        active: false,
        window: None,
    })
}

fn window_active(window: &WindowSpec, now_utc: DateTime<Utc>) -> Result<bool> {
    let tz = parse_tz(&window.tz)?;
    let local_now = tz.from_utc_datetime(&now_utc.naive_utc());
    let start = parse_time(&window.start)?;
    let end = parse_time(&window.end)?;
    let allowed_days = parse_days(&window.days)?;

    if start == end {
        return Ok(false);
    }

    if start < end {
        if !allowed_days.contains(&local_now.weekday()) {
            return Ok(false);
        }
        let current = local_now.time();
        return Ok(current >= start && current < end);
    }

    let current = local_now.time();
    if current >= start {
        return Ok(allowed_days.contains(&local_now.weekday()));
    }

    let previous_day = weekday_before(local_now.weekday());
    Ok(current < end && allowed_days.contains(&previous_day))
}

fn parse_tz(name: &str) -> Result<chrono::FixedOffset> {
    let normalized = name.trim();
    if normalized.eq_ignore_ascii_case("utc") {
        return Ok(chrono::FixedOffset::east_opt(0).expect("zero offset"));
    }
    if let Some(offset) = parse_fixed_offset(normalized) {
        return Ok(offset);
    }
    bail!("unsupported timezone {}", name)
}

fn parse_fixed_offset(value: &str) -> Option<chrono::FixedOffset> {
    let bytes = value.as_bytes();
    if bytes.len() != 6 || (bytes[0] != b'+' && bytes[0] != b'-') || bytes[3] != b':' {
        return None;
    }
    let sign = if bytes[0] == b'-' { -1 } else { 1 };
    let hours: i32 = value[1..3].parse().ok()?;
    let minutes: i32 = value[4..6].parse().ok()?;
    let total = sign * (hours * 3600 + minutes * 60);
    chrono::FixedOffset::east_opt(total)
}

fn parse_time(value: &str) -> Result<NaiveTime> {
    NaiveTime::parse_from_str(value.trim(), "%H:%M")
        .with_context(|| format!("invalid time {}", value))
}

fn parse_days(values: &[String]) -> Result<Vec<Weekday>> {
    values.iter().map(|day| parse_day(day)).collect()
}

fn parse_day(value: &str) -> Result<Weekday> {
    match value.trim() {
        "Mon" => Ok(Weekday::Mon),
        "Tue" => Ok(Weekday::Tue),
        "Wed" => Ok(Weekday::Wed),
        "Thu" => Ok(Weekday::Thu),
        "Fri" => Ok(Weekday::Fri),
        "Sat" => Ok(Weekday::Sat),
        "Sun" => Ok(Weekday::Sun),
        other => bail!("invalid day {}", other),
    }
}

fn weekday_before(day: Weekday) -> Weekday {
    match day {
        Weekday::Mon => Weekday::Sun,
        Weekday::Tue => Weekday::Mon,
        Weekday::Wed => Weekday::Tue,
        Weekday::Thu => Weekday::Wed,
        Weekday::Fri => Weekday::Thu,
        Weekday::Sat => Weekday::Fri,
        Weekday::Sun => Weekday::Sat,
    }
}

#[cfg(test)]
mod tests {
    use super::{is_now, WindowSet, WindowSpec};
    use chrono::{TimeZone, Utc};

    fn utc_window(start: &str, end: &str, days: &[&str]) -> WindowSet {
        WindowSet {
            windows: vec![WindowSpec {
                days: days.iter().map(|s| s.to_string()).collect(),
                start: start.to_string(),
                end: end.to_string(),
                tz: "UTC".to_string(),
            }],
        }
    }

    #[test]
    fn empty_windows_are_inactive() {
        let set = WindowSet { windows: vec![] };
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 2, 30, 0).unwrap()).expect("status");
        assert!(!status.active);
    }

    #[test]
    fn active_inside_same_day_window() {
        let set = utc_window("02:00", "06:00", &["Sat"]);
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 2, 30, 0).unwrap()).expect("status");
        assert!(status.active);
    }

    #[test]
    fn inactive_outside_window() {
        let set = utc_window("02:00", "06:00", &["Sat"]);
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 7, 0, 0).unwrap()).expect("status");
        assert!(!status.active);
    }

    #[test]
    fn active_across_midnight_uses_previous_day_membership() {
        let set = utc_window("22:00", "02:00", &["Sat"]);
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 17, 1, 30, 0).unwrap()).expect("status");
        assert!(status.active);
    }

    #[test]
    fn fixed_offset_zone_supported() {
        let set = WindowSet {
            windows: vec![WindowSpec {
                days: vec!["Sat".to_string()],
                start: "02:00".to_string(),
                end: "06:00".to_string(),
                tz: "+02:00".to_string(),
            }],
        };
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 1, 0, 0).unwrap()).expect("status");
        assert!(status.active);
    }

    #[test]
    fn same_start_end_is_inactive() {
        // start == end → always inactive (line 76)
        let set = utc_window("03:00", "03:00", &["Sat"]);
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 3, 0, 0).unwrap()).expect("status");
        assert!(!status.active);
    }

    #[test]
    fn midnight_span_current_after_start() {
        // start > end (22:00-02:00), current >= start → active if day matches (line 89)
        let set = utc_window("22:00", "02:00", &["Sat"]);
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 23, 0, 0).unwrap()).expect("status");
        assert!(status.active);
    }

    #[test]
    fn midnight_span_current_after_start_wrong_day_inactive() {
        // start > end, current >= start, but wrong day → inactive
        let set = utc_window("22:00", "02:00", &["Sat"]);
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 17, 23, 0, 0).unwrap()).expect("status");
        assert!(!status.active);
    }

    #[test]
    fn unsupported_timezone_errors() {
        // line 104: bail!("unsupported timezone")
        let set = WindowSet {
            windows: vec![WindowSpec {
                days: vec!["Sat".to_string()],
                start: "02:00".to_string(),
                end: "06:00".to_string(),
                tz: "America/New_York".to_string(),
            }],
        };
        let err = is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 3, 0, 0).unwrap()).unwrap_err();
        assert!(err.to_string().contains("unsupported timezone"));
    }

    #[test]
    fn invalid_day_name_errors() {
        // line 137: bail!("invalid day")
        let set = WindowSet {
            windows: vec![WindowSpec {
                days: vec!["Funday".to_string()],
                start: "02:00".to_string(),
                end: "06:00".to_string(),
                tz: "UTC".to_string(),
            }],
        };
        let err = is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 3, 0, 0).unwrap()).unwrap_err();
        assert!(err.to_string().contains("invalid day"));
    }

    #[test]
    fn negative_fixed_offset_zone() {
        let set = WindowSet {
            windows: vec![WindowSpec {
                days: vec!["Sat".to_string()],
                start: "02:00".to_string(),
                end: "06:00".to_string(),
                tz: "-05:00".to_string(),
            }],
        };
        // 07:00 UTC = 02:00 in -05:00
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 7, 0, 0).unwrap()).expect("status");
        assert!(status.active);
    }

    #[test]
    fn malformed_fixed_offset_falls_through() {
        // Bad offset format like "+2:00" (not 2-digit hour) → unsupported timezone
        let set = WindowSet {
            windows: vec![WindowSpec {
                days: vec!["Sat".to_string()],
                start: "02:00".to_string(),
                end: "06:00".to_string(),
                tz: "+2:00".to_string(),
            }],
        };
        let err = is_now(&set, Utc.with_ymd_and_hms(2026, 5, 16, 3, 0, 0).unwrap()).unwrap_err();
        assert!(err.to_string().contains("unsupported timezone"));
    }

    #[test]
    fn weekday_before_all_days() {
        // Cover all branches of weekday_before (lines 143-148)
        use super::weekday_before;
        use chrono::Weekday;
        assert_eq!(weekday_before(Weekday::Mon), Weekday::Sun);
        assert_eq!(weekday_before(Weekday::Tue), Weekday::Mon);
        assert_eq!(weekday_before(Weekday::Wed), Weekday::Tue);
        assert_eq!(weekday_before(Weekday::Thu), Weekday::Wed);
        assert_eq!(weekday_before(Weekday::Fri), Weekday::Thu);
        assert_eq!(weekday_before(Weekday::Sat), Weekday::Fri);
        assert_eq!(weekday_before(Weekday::Sun), Weekday::Sat);
    }

    #[test]
    fn window_identifier_includes_index() {
        let set = WindowSet {
            windows: vec![
                WindowSpec {
                    days: vec!["Mon".to_string()],
                    start: "01:00".to_string(),
                    end: "02:00".to_string(),
                    tz: "UTC".to_string(),
                },
                WindowSpec {
                    days: vec!["Tue".to_string()],
                    start: "01:00".to_string(),
                    end: "02:00".to_string(),
                    tz: "UTC".to_string(),
                },
            ],
        };
        // Monday 01:30 UTC
        let status =
            is_now(&set, Utc.with_ymd_and_hms(2026, 5, 18, 1, 30, 0).unwrap()).expect("status");
        assert!(status.active);
        assert_eq!(status.window.unwrap().identifier, "window-0");
    }
}
