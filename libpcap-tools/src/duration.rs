use std::ops::{Add, Sub};

/// Reimplementation of std::time::Duration, but panic-free
/// and partial, only to match our needs:
///   - use micros instead of nanos, avoid casts
///   - expose fields
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Duration {
    pub secs: u32,
    pub micros: u32,
}

pub const MICROS_PER_SEC: u32 = 1_000_000;

impl Duration {
    /// Build Duration from secs and micros
    pub fn new(secs: u32, micros: u32) -> Duration {
        Duration { secs, micros }
    }
    /// Test if Duration object is null
    #[inline]
    pub fn is_null(self) -> bool {
        self.secs == 0 && self.micros == 0
    }
}

impl Add for Duration {
    type Output = Duration;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, other: Duration) -> Self::Output {
        let secs = self.secs.wrapping_add(other.secs);
        let micros = self.micros.wrapping_add(other.micros);
        let (secs, micros) = if micros > MICROS_PER_SEC {
            (secs + (micros / MICROS_PER_SEC), micros % MICROS_PER_SEC)
        } else {
            (secs, micros)
        };

        Duration { secs, micros }
    }
}

impl Sub for Duration {
    type Output = Duration;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, other: Duration) -> Self::Output {
        let secs = self.secs.wrapping_sub(other.secs);
        let (secs, micros) = if self.micros >= other.micros {
            (secs, self.micros - other.micros)
        } else {
            let diff = other.micros.wrapping_sub(self.micros);
            let secs_less = diff / MICROS_PER_SEC;
            let micros = MICROS_PER_SEC - diff;
            (secs.wrapping_sub(1 + secs_less), micros)
        };

        Duration { secs, micros }
    }
}

#[cfg(test)]
mod tests {
    use super::Duration;
    #[test]
    fn duration_sub() {
        let d1 = Duration::new(1234, 5678);
        let d2 = Duration::new(1234, 6789);
        let d = d2 - d1;
        assert_eq!(d.secs, 0);
        assert_eq!(d.micros, 1111);
    }
}
