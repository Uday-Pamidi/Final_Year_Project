from datetime import datetime
from typing import Dict, Any, Optional
from app.config import (
    CTI_CORRELATION_THRESHOLD,
    ATTACK_CLASSES,
    ATTACK_CLASS_TO_ID
)
from app.models.schemas import CTIReport, CTITransferResult
from app.models.database import (
    save_cti_validated_sample,
    save_ioc_record,
    update_flow_cti_status,
    get_unincorporated_cti_samples
)

class CTITransferModel:
    """
    CTI Transfer Model (Core Innovation of Lin et al. IEEE TMLCN 2025):
    Processes unstructured/semi-structured CTI data and correlates it with
    real network flow sightings to generate validated, labeled training data
    for dynamic model adaptation.
    """

    def __init__(self, correlation_threshold: float = CTI_CORRELATION_THRESHOLD):
        self.correlation_threshold = correlation_threshold

    def calculate_correlation_score(
        self,
        flow_data: Dict[str, Any],
        cti_report: CTIReport
    ) -> float:
        """
        Calculates correlation score between network flow telemetry and CTI intelligence.
        Formula:
        Score = w1 * CTI_Confidence + w2 * (Threat_Score / 100) + w3 * Telemetry_Consistency
        """
        w1 = 0.40  # CTI feed reliability
        w2 = 0.35  # Threat severity
        w3 = 0.25  # Telemetry matching consistency

        cti_conf = float(cti_report.confidence)
        norm_threat = float(cti_report.threat_score) / 100.0

        # Check telemetry consistency (e.g. flow characteristics match attack category)
        features = flow_data.get("features", {})
        category = cti_report.attack_category

        telemetry_consistency = 0.70  # Default reasonable baseline consistency

        if category == "DoS_DDoS":
            if features.get("syn_flag_count", 0) > 10 or features.get("flow_packets_s", 0) > 500:
                telemetry_consistency = 0.95
            elif features.get("rst_flag_count", 0) > 10:
                telemetry_consistency = 0.90
        elif category == "PortScan":
            if features.get("flow_duration", 0) < 0.1 or features.get("total_fwd_packets", 0) <= 3:
                telemetry_consistency = 0.92
        elif category == "Botnet_C2":
            if features.get("payload_entropy", 0) > 5.5 or features.get("down_up_ratio", 0) > 2.0:
                telemetry_consistency = 0.96
        elif category == "BruteForce":
            if features.get("total_fwd_packets", 0) > 15 and features.get("packet_length_mean", 0) < 150:
                telemetry_consistency = 0.93
        elif category == "Infiltration_Web":
            if features.get("payload_entropy", 0) > 4.5 or features.get("total_fwd_bytes", 0) > 800:
                telemetry_consistency = 0.91

        correlation = (w1 * cti_conf) + (w2 * norm_threat) + (w3 * telemetry_consistency)
        return round(float(correlation), 4)

    def process_and_transfer(
        self,
        flow_id: str,
        flow_data: Dict[str, Any],
        cti_report: Optional[CTIReport]
    ) -> CTITransferResult:
        if not cti_report:
            return CTITransferResult(
                flow_id=flow_id,
                ioc_value=flow_data.get("src_ip", "Unknown"),
                cti_threat_score=0,
                correlation_confidence=0.0,
                is_validated=False,
                assigned_label="Uncorrelated_Anomaly",
                transfer_status="No CTI Intelligence Match",
                explanation="No relevant Indicators of Compromise found in threat intelligence repositories."
            )

        correlation_conf = self.calculate_correlation_score(flow_data, cti_report)
        is_validated = bool(correlation_conf >= self.correlation_threshold)

        # Map to valid IDS class
        attack_label = cti_report.attack_category
        if attack_label not in ATTACK_CLASS_TO_ID:
            attack_label = "Infiltration_Web"  # Fallback valid class
        class_id = ATTACK_CLASS_TO_ID[attack_label]

        # Record IoC query
        save_ioc_record({
            "flow_id": flow_id,
            "ioc_value": cti_report.ioc_value,
            "ioc_type": cti_report.ioc_type,
            "threat_score": cti_report.threat_score,
            "threat_level": cti_report.threat_level,
            "malware_family": cti_report.malware_family,
            "attack_category": attack_label,
            "confidence": correlation_conf,
            "cve_list": cti_report.cve_list,
            "sources": cti_report.sources,
            "description": cti_report.description,
            "correlated": is_validated
        })

        if is_validated:
            status = "Validated Ground Truth Generated"
            explanation = (
                f"CTI Transfer Model correlated threat intelligence ({cti_report.malware_family}, "
                f"Threat Score {cti_report.threat_score}) with network sighting telemetry. "
                f"Correlation confidence {correlation_conf:.2f} >= threshold {self.correlation_threshold:.2f}. "
                f"Flow transformed into verified '{attack_label}' training sample."
            )
            # Store in CTI Validated Samples table for dynamic model retraining
            save_cti_validated_sample({
                "flow_id": flow_id,
                "features": flow_data.get("features", {}),
                "validated_label": attack_label,
                "validated_class_id": class_id,
                "correlation_confidence": correlation_conf,
                "cti_threat_score": cti_report.threat_score,
                "ioc_value": cti_report.ioc_value
            })
            # Update flow record in database
            update_flow_cti_status(flow_id, cti_matched=True, threat_score=cti_report.threat_score, validated_label=attack_label)
        else:
            status = "Low Correlation Confidence"
            explanation = (
                f"CTI report found ({cti_report.malware_family}) but correlation confidence "
                f"({correlation_conf:.2f}) was below threshold ({self.correlation_threshold:.2f}). Sample quarantined."
            )
            update_flow_cti_status(flow_id, cti_matched=True, threat_score=cti_report.threat_score)

        return CTITransferResult(
            flow_id=flow_id,
            ioc_value=cti_report.ioc_value,
            cti_threat_score=cti_report.threat_score,
            correlation_confidence=correlation_conf,
            is_validated=is_validated,
            assigned_label=attack_label if is_validated else "Quarantined_Anomaly",
            transfer_status=status,
            explanation=explanation
        )

    def get_pending_sample_count(self) -> int:
        samples = get_unincorporated_cti_samples()
        return len(samples)
