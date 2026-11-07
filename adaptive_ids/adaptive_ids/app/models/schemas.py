from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime

class NetworkFlowIn(BaseModel):
    # Metadata
    src_ip: Optional[str] = "192.168.1.105"
    dst_ip: Optional[str] = "10.0.0.1"
    src_port: Optional[int] = 49821
    dst_port: Optional[int] = 80
    protocol: Optional[str] = "TCP"  # TCP, UDP, ICMP

    # 16 Core Flow Features
    flow_duration: float = Field(..., description="Flow duration in seconds")
    total_fwd_packets: float = Field(..., description="Number of packets forward")
    total_bwd_packets: float = Field(..., description="Number of packets backward")
    total_fwd_bytes: float = Field(..., description="Total payload bytes forward")
    total_bwd_bytes: float = Field(..., description="Total payload bytes backward")
    packet_length_mean: float = Field(..., description="Mean packet length")
    packet_length_std: float = Field(..., description="Standard deviation packet length")
    flow_bytes_s: float = Field(..., description="Flow bytes per second")
    flow_packets_s: float = Field(..., description="Flow packets per second")
    syn_flag_count: float = Field(..., description="SYN flags count")
    fin_flag_count: float = Field(..., description="FIN flags count")
    rst_flag_count: float = Field(..., description="RST flags count")
    psh_flag_count: float = Field(..., description="PSH flags count")
    ack_flag_count: float = Field(..., description="ACK flags count")
    down_up_ratio: float = Field(..., description="Download/Upload ratio")
    payload_entropy: float = Field(..., description="Payload Shannon Entropy (0-8)")

    # Ground truth (if known/testing)
    ground_truth: Optional[str] = None

class PredictionResult(BaseModel):
    flow_id: str
    timestamp: str
    predicted_class: str
    predicted_class_id: int
    confidence: float
    probabilities: Dict[str, float]
    is_anomaly: bool
    anomaly_score: float
    is_uncertain: bool
    requires_cti: bool
    status: str  # Normal, Known Threat, Anomaly / Low Confidence
    ioc_extracted: Optional[Dict[str, Any]] = None

class IoCData(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    flow_hash: str
    payload_entropy: float
    flag_signature: str

class CTIReport(BaseModel):
    ioc_value: str
    ioc_type: str  # IP, Port, Hash
    threat_score: int  # 0 - 100
    threat_level: str  # Critical, High, Medium, Low, Benign
    malware_family: str
    attack_category: str
    confidence: float  # 0.0 - 1.0
    cve_list: List[str]
    sources: List[str]
    description: str
    tags: List[str]
    first_seen: str
    last_seen: str

class CTITransferResult(BaseModel):
    flow_id: str
    ioc_value: str
    cti_threat_score: int
    correlation_confidence: float
    is_validated: bool
    assigned_label: str
    transfer_status: str
    explanation: str

class FeatureDriftMetric(BaseModel):
    feature: str
    ks_statistic: float
    p_value: float
    psi_score: float
    is_drift: bool
    status: str

class DriftAnalysisResult(BaseModel):
    overall_status: str  # STABLE, WARNING, DRIFT_DETECTED
    drift_detected: bool
    active_window_size: int
    baseline_window_size: int
    drifting_features: List[str]
    metrics: List[FeatureDriftMetric]
    adwin_drift_signal: bool
    timestamp: str

class ModelVersionInfo(BaseModel):
    version: str
    timestamp: str
    trigger_reason: str
    total_training_samples: int
    cti_samples_incorporated: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    is_active: bool

class RetrainResponse(BaseModel):
    success: bool
    old_version: str
    new_version: str
    trigger_reason: str
    samples_added: int
    before_metrics: Dict[str, float]
    after_metrics: Dict[str, float]
    message: str

class FlowExplainResponse(BaseModel):
    flow_id: str
    predicted_label: str
    confidence: float
    base_value: float
    feature_contributions: List[Dict[str, Any]]  # [{feature, value, shap_value, direction}]
    analyst_summary: str

class SimulationBatchRequest(BaseModel):
    count: int = Field(default=10, ge=1, le=500)
    traffic_type: str = Field(default="mixed", description="benign, dos, portscan, bruteforce, botnet, web, zero_day, mixed, drifting")
