//! Aggregate Prometheus gauges from the canonical observation snapshot.

use std::fmt::Write;

use serde_json::Value;

pub(crate) fn prometheus(snapshot: &Value) -> String {
    let mut text = String::new();
    for (name, description, pointer) in [
        (
            "pathchord_active_sessions",
            "Current active Sessions.",
            "/runtime/sessions",
        ),
        (
            "pathchord_ready_paths",
            "Current ready Paths.",
            "/runtime/ready_paths",
        ),
        (
            "pathchord_active_streams",
            "Current active Streams.",
            "/runtime/streams",
        ),
        (
            "pathchord_target_connections",
            "Current target connections.",
            "/runtime/target_connections",
        ),
        (
            "pathchord_observed_nodes",
            "Nodes in the observation snapshot.",
            "/nodes",
        ),
        (
            "pathchord_observed_connections",
            "Connections in the observation snapshot.",
            "/connections",
        ),
        (
            "pathchord_observation_generation",
            "Observation snapshot generation.",
            "/generation",
        ),
        (
            "pathchord_observed_paths",
            "Paths represented in the observation snapshot.",
            "/paths",
        ),
        (
            "pathchord_observed_streams",
            "Streams represented in the observation snapshot.",
            "/streams_observed",
        ),
        (
            "pathchord_stream_bytes_sent",
            "Bytes sent by streams in the bounded observation snapshot.",
            "/stream_totals/bytes_sent",
        ),
        (
            "pathchord_stream_bytes_received",
            "Bytes received by streams in the bounded observation snapshot.",
            "/stream_totals/bytes_received",
        ),
        (
            "pathchord_stream_bytes_acked",
            "Bytes acknowledged for streams in the bounded observation snapshot.",
            "/stream_totals/bytes_acked",
        ),
        (
            "pathchord_stream_retransmissions",
            "Stream retransmissions in the bounded observation snapshot.",
            "/stream_totals/retransmissions",
        ),
        (
            "pathchord_path_rtt_ms_sum",
            "Sum of observed Path RTT values in milliseconds.",
            "/path_quality/rtt_ms_sum",
        ),
        (
            "pathchord_path_jitter_ms_sum",
            "Sum of observed Path jitter values in milliseconds.",
            "/path_quality/jitter_ms_sum",
        ),
        (
            "pathchord_path_loss_ppm_sum",
            "Sum of observed Path loss values in parts per million.",
            "/path_quality/loss_ppm_sum",
        ),
        (
            "pathchord_path_throughput_bps_sum",
            "Sum of observed Path throughput values in bits per second.",
            "/path_quality/throughput_bps_sum",
        ),
        (
            "pathchord_path_reordering_events",
            "Observed Path reordering events.",
            "/path_quality/reordering_events",
        ),
    ] {
        if let Some(value) = snapshot.pointer(pointer).and_then(Value::as_u64) {
            let _ = writeln!(
                text,
                "# HELP {name} {description}\n# TYPE {name} gauge\n{name} {value}"
            );
        }
    }
    for (state, pointer) in [
        ("unknown", "/node_health/unknown"),
        ("up", "/node_health/up"),
        ("degraded", "/node_health/degraded"),
        ("down", "/node_health/down"),
    ] {
        if let Some(value) = snapshot.pointer(pointer).and_then(Value::as_u64) {
            let name = format!("pathchord_nodes_{state}");
            let _ = writeln!(
                text,
                "# HELP {name} Nodes currently in the {state} health state.\n# TYPE {name} gauge\n{name} {value}"
            );
        }
    }
    text
}

#[cfg(test)]
mod tests {
    #[test]
    fn exports_gauges_without_turning_targets_or_admin_tags_into_labels() {
        let result = super::prometheus(&serde_json::json!({
            "runtime": {"sessions": 3, "ready_paths": 2, "streams": 7, "target_connections": 8},
            "nodes": 4, "connections": 8, "generation": 42,
            "paths": 2, "streams_observed": 3,
            "node_health": {"unknown": 1, "up": 2, "degraded": 1, "down": 0},
            "path_quality": {"rtt_ms_sum": 25, "jitter_ms_sum": 5, "loss_ppm_sum": 4000, "throughput_bps_sum": 1000, "reordering_events": 2},
            "stream_totals": {"bytes_sent": 10, "bytes_received": 11, "bytes_acked": 9, "retransmissions": 1},
            "private_target": "private.example", "admin": {"owner": "arbitrary-label"},
        }));
        assert!(
            result.contains("# TYPE pathchord_active_streams gauge\npathchord_active_streams 7\n")
        );
        assert!(result.contains("pathchord_observation_generation 42\n"));
        assert!(result.contains("pathchord_nodes_up 2\n"));
        assert!(result.contains("pathchord_stream_bytes_sent 10\n"));
        assert!(!result.contains("private.example"));
        assert!(!result.contains("arbitrary-label"));
    }
}
