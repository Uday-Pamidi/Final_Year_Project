import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from app.config import DATABASE_PATH

def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Network flows table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS flows (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        features_json TEXT,
        predicted_class TEXT,
        predicted_class_id INTEGER,
        confidence REAL,
        is_anomaly INTEGER,
        anomaly_score REAL,
        is_uncertain INTEGER,
        requires_cti INTEGER,
        ground_truth TEXT,
        cti_matched INTEGER DEFAULT 0,
        cti_threat_score INTEGER DEFAULT 0,
        status TEXT
    )
    """)

    # Extracted IoCs & CTI queries table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ioc_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_id TEXT,
        ioc_value TEXT,
        ioc_type TEXT,
        extracted_at TEXT,
        threat_score INTEGER,
        threat_level TEXT,
        malware_family TEXT,
        attack_category TEXT,
        confidence REAL,
        cve_list_json TEXT,
        sources_json TEXT,
        description TEXT,
        correlated INTEGER DEFAULT 0
    )
    """)

    # CTI Validated Ground Truth Samples buffer for model retraining
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cti_validated_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_id TEXT UNIQUE,
        timestamp TEXT,
        features_json TEXT,
        validated_label TEXT,
        validated_class_id INTEGER,
        correlation_confidence REAL,
        cti_threat_score INTEGER,
        ioc_value TEXT,
        incorporated INTEGER DEFAULT 0
    )
    """)

    # Model Version Registry
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS model_versions (
        version TEXT PRIMARY KEY,
        timestamp TEXT,
        trigger_reason TEXT,
        total_training_samples INTEGER,
        cti_samples_incorporated INTEGER,
        accuracy REAL,
        precision REAL,
        recall REAL,
        f1_score REAL,
        is_active INTEGER DEFAULT 0
    )
    """)

    # Concept Drift History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS drift_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        overall_status TEXT,
        drift_detected INTEGER,
        drifting_features_json TEXT,
        avg_ks_statistic REAL,
        min_p_value REAL,
        window_size INTEGER
    )
    """)

    conn.commit()
    conn.close()

def save_flow(flow: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO flows (
        id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
        features_json, predicted_class, predicted_class_id, confidence,
        is_anomaly, anomaly_score, is_uncertain, requires_cti, ground_truth,
        cti_matched, cti_threat_score, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        flow["id"],
        flow.get("timestamp", datetime.utcnow().isoformat()),
        flow.get("src_ip", "192.168.1.100"),
        flow.get("dst_ip", "10.0.0.1"),
        flow.get("src_port", 50000),
        flow.get("dst_port", 80),
        flow.get("protocol", "TCP"),
        json.dumps(flow.get("features", {})),
        flow.get("predicted_class", "Benign"),
        flow.get("predicted_class_id", 0),
        float(flow.get("confidence", 0.0)),
        1 if flow.get("is_anomaly") else 0,
        float(flow.get("anomaly_score", 0.0)),
        1 if flow.get("is_uncertain") else 0,
        1 if flow.get("requires_cti") else 0,
        flow.get("ground_truth"),
        1 if flow.get("cti_matched") else 0,
        int(flow.get("cti_threat_score", 0)),
        flow.get("status", "Normal")
    ))
    conn.commit()
    conn.close()

def update_flow_cti_status(flow_id: str, cti_matched: bool, threat_score: int, validated_label: str = None):
    conn = get_connection()
    cursor = conn.cursor()
    if validated_label:
        cursor.execute("""
        UPDATE flows 
        SET cti_matched = ?, cti_threat_score = ?, predicted_class = ?, status = 'CTI Correlated'
        WHERE id = ?
        """, (1 if cti_matched else 0, threat_score, validated_label, flow_id))
    else:
        cursor.execute("""
        UPDATE flows 
        SET cti_matched = ?, cti_threat_score = ?
        WHERE id = ?
        """, (1 if cti_matched else 0, threat_score, flow_id))
    conn.commit()
    conn.close()

def get_recent_flows(limit: int = 50, threat_only: bool = False) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM flows"
    params = []
    if threat_only:
        query += " WHERE predicted_class != 'Benign' OR is_anomaly = 1 OR requires_cti = 1"
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["features"] = json.loads(d["features_json"]) if d["features_json"] else {}
        d["is_anomaly"] = bool(d["is_anomaly"])
        d["is_uncertain"] = bool(d["is_uncertain"])
        d["requires_cti"] = bool(d["requires_cti"])
        d["cti_matched"] = bool(d["cti_matched"])
        results.append(d)
    conn.close()
    return results

def get_flow_by_id(flow_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM flows WHERE id = ?", (flow_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["features"] = json.loads(d["features_json"]) if d["features_json"] else {}
    d["is_anomaly"] = bool(d["is_anomaly"])
    d["is_uncertain"] = bool(d["is_uncertain"])
    d["requires_cti"] = bool(d["requires_cti"])
    d["cti_matched"] = bool(d["cti_matched"])
    return d

def save_ioc_record(record: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO ioc_records (
        flow_id, ioc_value, ioc_type, extracted_at, threat_score, threat_level,
        malware_family, attack_category, confidence, cve_list_json, sources_json,
        description, correlated
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record.get("flow_id"),
        record.get("ioc_value"),
        record.get("ioc_type", "IP"),
        record.get("extracted_at", datetime.utcnow().isoformat()),
        record.get("threat_score", 0),
        record.get("threat_level", "Unknown"),
        record.get("malware_family", "Unknown"),
        record.get("attack_category", "Unknown"),
        record.get("confidence", 0.0),
        json.dumps(record.get("cve_list", [])),
        json.dumps(record.get("sources", [])),
        record.get("description", ""),
        1 if record.get("correlated") else 0
    ))
    conn.commit()
    conn.close()

def get_recent_ioc_records(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ioc_records ORDER BY extracted_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["cve_list"] = json.loads(d["cve_list_json"]) if d["cve_list_json"] else []
        d["sources"] = json.loads(d["sources_json"]) if d["sources_json"] else []
        d["correlated"] = bool(d["correlated"])
        results.append(d)
    conn.close()
    return results

def save_cti_validated_sample(sample: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO cti_validated_samples (
        flow_id, timestamp, features_json, validated_label, validated_class_id,
        correlation_confidence, cti_threat_score, ioc_value, incorporated
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
    """, (
        sample["flow_id"],
        sample.get("timestamp", datetime.utcnow().isoformat()),
        json.dumps(sample["features"]),
        sample["validated_label"],
        sample["validated_class_id"],
        sample["correlation_confidence"],
        sample.get("cti_threat_score", 85),
        sample.get("ioc_value", "")
    ))
    conn.commit()
    conn.close()

def get_unincorporated_cti_samples() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cti_validated_samples WHERE incorporated = 0")
    rows = cursor.fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["features"] = json.loads(d["features_json"])
        results.append(d)
    conn.close()
    return results

def mark_cti_samples_incorporated(sample_ids: List[int]):
    if not sample_ids:
        return
    conn = get_connection()
    cursor = conn.cursor()
    placeholders = ",".join(["?"] * len(sample_ids))
    cursor.execute(f"UPDATE cti_validated_samples SET incorporated = 1 WHERE id IN ({placeholders})", sample_ids)
    conn.commit()
    conn.close()

def save_model_version(version_info: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    # Mark all others as inactive
    cursor.execute("UPDATE model_versions SET is_active = 0")
    cursor.execute("""
    INSERT OR REPLACE INTO model_versions (
        version, timestamp, trigger_reason, total_training_samples,
        cti_samples_incorporated, accuracy, precision, recall, f1_score, is_active
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    """, (
        version_info["version"],
        version_info.get("timestamp", datetime.utcnow().isoformat()),
        version_info.get("trigger_reason", "Initial Base Training"),
        version_info.get("total_training_samples", 0),
        version_info.get("cti_samples_incorporated", 0),
        version_info.get("accuracy", 0.0),
        version_info.get("precision", 0.0),
        version_info.get("recall", 0.0),
        version_info.get("f1_score", 0.0)
    ))
    conn.commit()
    conn.close()

def get_model_versions() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM model_versions ORDER BY timestamp ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_active_model_version() -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM model_versions WHERE is_active = 1 LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def log_drift(drift_data: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO drift_logs (
        timestamp, overall_status, drift_detected, drifting_features_json,
        avg_ks_statistic, min_p_value, window_size
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        drift_data.get("timestamp", datetime.utcnow().isoformat()),
        drift_data.get("overall_status", "STABLE"),
        1 if drift_data.get("drift_detected") else 0,
        json.dumps(drift_data.get("drifting_features", [])),
        drift_data.get("avg_ks_statistic", 0.0),
        drift_data.get("min_p_value", 1.0),
        drift_data.get("window_size", 100)
    ))
    conn.commit()
    conn.close()

def get_recent_drift_logs(limit: int = 15) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM drift_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["drifting_features"] = json.loads(d["drifting_features_json"]) if d["drifting_features_json"] else []
        d["drift_detected"] = bool(d["drift_detected"])
        results.append(d)
    conn.close()
    return results

def get_dashboard_stats() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM flows")
    total_flows = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM flows WHERE predicted_class != 'Benign'")
    attacks_detected = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM flows WHERE is_anomaly = 1")
    anomalies_detected = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM flows WHERE requires_cti = 1")
    cti_queries = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM cti_validated_samples")
    cti_validated = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM cti_validated_samples WHERE incorporated = 0")
    cti_buffer_pending = cursor.fetchone()[0]

    cursor.execute("""
    SELECT predicted_class, COUNT(*) as cnt 
    FROM flows 
    GROUP BY predicted_class
    """)
    distribution = {r["predicted_class"]: r["cnt"] for r in cursor.fetchall()}

    conn.close()

    return {
        "total_flows": total_flows,
        "attacks_detected": attacks_detected,
        "anomalies_detected": anomalies_detected,
        "cti_queries": cti_queries,
        "cti_validated": cti_validated,
        "cti_buffer_pending": cti_buffer_pending,
        "distribution": distribution
    }
