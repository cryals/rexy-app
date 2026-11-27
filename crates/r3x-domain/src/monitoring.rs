use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeRange {
    OneMin,
    FiveMin,
    FifteenMin,
    OneHour,
}

impl TimeRange {
    #[must_use]
    pub fn seconds(self) -> u64 {
        match self {
            Self::OneMin => 60,
            Self::FiveMin => 300,
            Self::FifteenMin => 900,
            Self::OneHour => 3600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrafficSample {
    pub timestamp: DateTime<Utc>,
    pub down_bps: u64,
    pub up_bps: u64,
    pub total_down_bytes: u64,
    pub total_up_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatencySample {
    pub timestamp: DateTime<Utc>,
    pub rtt_ms: Option<u32>,
    pub jitter_ms: Option<f32>,
    pub packet_loss_pct: Option<f32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceSample {
    pub timestamp: DateTime<Utc>,
    pub ui_cpu_pct: Option<f32>,
    pub core_cpu_pct: Option<f32>,
    pub ui_rss_bytes: Option<u64>,
    pub core_rss_bytes: Option<u64>,
}

/// Bounded ring buffer ensuring telemetry history never grows unboundedly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingBuffer<T> {
    capacity: usize,
    items: VecDeque<T>,
}

impl<T> RingBuffer<T> {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            items: VecDeque::with_capacity(cap),
        }
    }

    pub fn push(&mut self, value: T) {
        if self.items.len() == self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(value);
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    #[must_use]
    pub fn latest(&self) -> Option<&T> {
        self.items.back()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub down_bps: Option<u64>,
    pub up_bps: Option<u64>,
    pub total_down_bytes: Option<u64>,
    pub total_up_bytes: Option<u64>,
    pub session_duration_secs: Option<u64>,
    pub latency_ms: Option<u32>,
    pub jitter_ms: Option<f32>,
    pub packet_loss_pct: Option<f32>,
    pub core_uptime_secs: Option<u64>,
    pub ui_cpu_pct: Option<f32>,
    pub core_cpu_pct: Option<f32>,
    pub ui_rss_bytes: Option<u64>,
    pub core_rss_bytes: Option<u64>,
    pub active_connections: Option<usize>,
    pub proxied_connections: Option<usize>,
    pub direct_connections: Option<usize>,
    pub blocked_connections: Option<usize>,
    pub reconnect_count: u32,
    pub failed_connections: u32,
}
