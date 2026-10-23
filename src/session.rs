//! Attack sessions: all activity from one source IP until it goes idle.

use std::{
    net::IpAddr,
    num::NonZeroUsize,
    sync::Mutex,
    time::{Duration, Instant},
};

use lru::LruCache;
use uuid::Uuid;

pub struct AttackSessions {
    idle: Duration,
    sessions: Mutex<LruCache<IpAddr, (Uuid, Instant)>>,
}

impl AttackSessions {
    /// Tracks at most `capacity` sources, evicting the least recently active.
    pub fn new(idle: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            idle,
            sessions: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// Returns the attack session for `ip`, starting a new one if the source
    /// is unknown or has been idle longer than the idle window.
    pub fn touch(&self, ip: IpAddr) -> Uuid {
        self.touch_at(ip, Instant::now())
    }

    fn touch_at(&self, ip: IpAddr, now: Instant) -> Uuid {
        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        if let Some((id, last)) = sessions.get_mut(&ip)
            && now.duration_since(*last) <= self.idle
        {
            *last = now;
            return *id;
        }
        let id = Uuid::now_v7();
        sessions.put(ip, (id, now));
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn activity_within_idle_window_extends_the_session() {
        let s = AttackSessions::new(Duration::from_secs(300), NonZeroUsize::new(10).unwrap());
        let t0 = Instant::now();
        let a = s.touch_at(ip("192.0.2.1"), t0);
        // Each touch resets the window, so 2 × 200 s stays one session.
        assert_eq!(a, s.touch_at(ip("192.0.2.1"), t0 + Duration::from_secs(200)));
        assert_eq!(a, s.touch_at(ip("192.0.2.1"), t0 + Duration::from_secs(400)));
        assert_ne!(a, s.touch_at(ip("192.0.2.2"), t0 + Duration::from_secs(400)));
    }

    #[test]
    fn idle_gap_starts_a_new_session() {
        let s = AttackSessions::new(Duration::from_secs(300), NonZeroUsize::new(10).unwrap());
        let t0 = Instant::now();
        let a = s.touch_at(ip("192.0.2.1"), t0);
        assert_ne!(a, s.touch_at(ip("192.0.2.1"), t0 + Duration::from_secs(301)));
    }

    #[test]
    fn capacity_evicts_least_recently_active_source() {
        let s = AttackSessions::new(Duration::from_secs(300), NonZeroUsize::new(2).unwrap());
        let t0 = Instant::now();
        let a = s.touch_at(ip("192.0.2.1"), t0);
        let b = s.touch_at(ip("192.0.2.2"), t0);
        s.touch_at(ip("192.0.2.1"), t0); // .2 is now least recent
        s.touch_at(ip("192.0.2.3"), t0); // evicts .2
        assert_eq!(a, s.touch_at(ip("192.0.2.1"), t0));
        assert_ne!(b, s.touch_at(ip("192.0.2.2"), t0));
    }
}
