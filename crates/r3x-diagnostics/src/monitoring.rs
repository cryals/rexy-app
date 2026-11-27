use chrono::{Duration as ChronoDuration, Utc};
use parking_lot::RwLock;
use r3x_domain::{LatencySample, R3xError, ResourceSample, RingBuffer, TimeRange, TrafficSample};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::net::TcpStream;

struct TelemetryState {
    traffic: RingBuffer<TrafficSample>,
    latency: RingBuffer<LatencySample>,
    resources: RingBuffer<ResourceSample>,
    paused: bool,
    sys: Option<System>,
}

pub struct TelemetryHub {
    state: RwLock<TelemetryState>,
}

impl Default for TelemetryHub {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryHub {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(TelemetryState {
                traffic: RingBuffer::new(3600),
                latency: RingBuffer::new(600),
                resources: RingBuffer::new(600),
                paused: false,
                sys: System::new().ok(),
            }),
        }
    }

    pub fn set_paused(&self, paused: bool) {
        self.state.write().paused = paused;
    }

    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.state.read().paused
    }

    pub fn clear(&self) {
        let mut guard = self.state.write();
        guard.traffic.clear();
        guard.latency.clear();
        guard.resources.clear();
    }

    pub fn record_traffic(&self, sample: TrafficSample) {
        let mut guard = self.state.write();
        if !guard.paused {
            guard.traffic.push(sample);
        }
    }

    pub fn record_latency(&self, sample: LatencySample) {
        let mut guard = self.state.write();
        if !guard.paused {
            guard.latency.push(sample);
        }
    }

    #[must_use]
    pub fn sample_resources(&self, core_pid: Option<u32>) -> ResourceSample {
        let mut guard = self.state.write();
        let ui_pid = Pid::from_u32(std::process::id());
        let target_core_pid = core_pid.filter(|&p| p > 0).map(Pid::from_u32);

        let mut pids = vec![ui_pid];
        if let Some(cp) = target_core_pid {
            pids.push(cp);
        }

        let (ui_cpu_pct, ui_rss_bytes, core_cpu_pct, core_rss_bytes) =
            if let Some(ref mut sys) = guard.sys {
                sys.refresh_processes_specifics(
                    ProcessesToUpdate::Some(&pids),
                    true,
                    ProcessRefreshKind::everything(),
                );
                let (u_cpu, u_rss) = sys
                    .process(ui_pid)
                    .map(|p| (Some(p.cpu_usage()), Some(p.memory())))
                    .unwrap_or((None, None));
                let (c_cpu, c_rss) = target_core_pid
                    .and_then(|cp| sys.process(cp))
                    .map(|p| (Some(p.cpu_usage()), Some(p.memory())))
                    .unwrap_or((None, None));
                (u_cpu, u_rss, c_cpu, c_rss)
            } else {
                (None, None, None, None)
            };

        let sample = ResourceSample {
            timestamp: Utc::now(),
            ui_cpu_pct,
            core_cpu_pct,
            ui_rss_bytes,
            core_rss_bytes,
        };
        if !guard.paused {
            guard.resources.push(sample.clone());
        }
        sample
    }

    #[must_use]
    pub fn traffic_for_range(&self, range: TimeRange) -> Vec<TrafficSample> {
        let guard = self.state.read();
        let cutoff = Utc::now() - ChronoDuration::seconds(range.seconds() as i64);
        guard
            .traffic
            .iter()
            .filter(|s| s.timestamp >= cutoff)
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn latest_resources(&self) -> Option<ResourceSample> {
        self.state.read().resources.latest().cloned()
    }

    #[must_use]
    pub fn latest_latency(&self) -> Option<LatencySample> {
        self.state.read().latency.latest().cloned()
    }

    #[must_use]
    pub fn traffic_len(&self) -> usize {
        self.state.read().traffic.len()
    }
}

pub async fn measure_tcp_latency(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<u32, R3xError> {
    if host.trim().is_empty() || port == 0 {
        return Err(R3xError::Validation(
            "invalid host or port for TCP latency probe".to_owned(),
        ));
    }
    let target = format!("{}:{port}", host.trim());
    let start = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(&target)).await {
        Ok(Ok(_)) => {
            let ms = start.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
            Ok(ms.max(1))
        }
        Ok(Err(e)) => Err(R3xError::Network(format!(
            "TCP latency probe to {target} failed: {e}"
        ))),
        Err(_) => Err(R3xError::Timeout(timeout.as_millis() as u64)),
    }
}

#[must_use]
pub fn build_line_path(values: &[f64], width: f32, height: f32, max_y: Option<f64>) -> String {
    if values.len() < 2
        || !width.is_finite()
        || !height.is_finite()
        || width <= 0.0
        || height <= 8.0
    {
        return String::new();
    }

    let computed_max = max_y
        .filter(|m| m.is_finite() && *m > 0.0)
        .unwrap_or_else(|| {
            values
                .iter()
                .copied()
                .filter(|v| v.is_finite() && *v >= 0.0)
                .fold(1.0_f64, f64::max)
        });

    let pad_y = 6.0_f32;
    let usable_h = (height - pad_y * 2.0).max(1.0);
    let step_x = width / ((values.len() - 1) as f32);

    let mut out = String::new();
    for (idx, &raw_val) in values.iter().enumerate() {
        let clamped = if raw_val.is_finite() && raw_val >= 0.0 {
            raw_val.min(computed_max)
        } else {
            0.0
        };
        let norm = (clamped / computed_max) as f32;
        let x = ((idx as f32) * step_x).clamp(0.0, width);
        let y = (height - pad_y - norm * usable_h).clamp(pad_y, height - pad_y);
        if idx == 0 {
            out.push_str(&format!("M {x:.2} {y:.2}"));
        } else {
            out.push_str(&format!(" L {x:.2} {y:.2}"));
        }
    }
    out
}

#[must_use]
pub fn build_area_path(values: &[f64], width: f32, height: f32, max_y: Option<f64>) -> String {
    let line = build_line_path(values, width, height, max_y);
    if line.is_empty() {
        return String::new();
    }
    format!("{line} L {width:.2} {height:.2} L 0.00 {height:.2} Z")
}
