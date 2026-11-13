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
    ] {
        if let Some(value) = snapshot.pointer(pointer).and_then(Value::as_u64) {
            let _ = writeln!(
                text,
                "# HELP {name} {description}\n# TYPE {name} gauge\n{name} {value}"
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
            "private_target": "private.example", "admin": {"owner": "arbitrary-label"},
        }));
        assert!(
            result.contains("# TYPE pathchord_active_streams gauge\npathchord_active_streams 7\n")
        );
        assert!(result.contains("pathchord_observation_generation 42\n"));
        assert!(!result.contains("private.example"));
        assert!(!result.contains("arbitrary-label"));
    }
}
