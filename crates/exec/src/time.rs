/// Local wall-clock time: log file names, test run ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    pub year: u16,
    pub month: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
}

impl LocalTime {
    pub fn now() -> Self {
        // SAFETY: `time` only writes its own struct, `localtime_r` fills a struct we own.
        let mut t = libc::tm {
            tm_year: 0,
            tm_mon: 0,
            tm_mday: 0,
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: std::ptr::null_mut(),
        };
        let now = unsafe { libc::time(std::ptr::null_mut()) };
        // SAFETY: `libc::time` has no preconditions; `t` is a valid struct of the right type.
        unsafe { libc::localtime_r(&now, &mut t) };
        Self {
            year: (t.tm_year + 1900) as u16,
            month: (t.tm_mon + 1) as u16,
            day: t.tm_mday as u16,
            hour: t.tm_hour as u16,
            minute: t.tm_min as u16,
            second: t.tm_sec as u16,
        }
    }

    /// `2026-10-10`
    pub fn date(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// `2026-10-10_05-03-34`: how `test zapret.ps1` names its results.
    pub fn stamp(&self) -> String {
        format!(
            "{}_{:02}-{:02}-{:02}",
            self.date(),
            self.hour,
            self.minute,
            self.second
        )
    }

    /// `05:03:34`
    pub fn clock(&self) -> String {
        format!("{:02}:{:02}:{:02}", self.hour, self.minute, self.second)
    }
}
