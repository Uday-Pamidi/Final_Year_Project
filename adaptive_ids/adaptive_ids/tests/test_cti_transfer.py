import pytest
from app.core.cti_engine import CTIEngine
from app.core.cti_transfer import CTITransferModel
from app.models.schemas import CTIReport
from app.models.database import init_db

def test_cti_engine_query():
    init_db()
    engine = CTIEngine()
    
    # Test known threat IP
    report = engine.query_ioc({"src_ip": "198.51.100.42", "dst_port": 4444, "payload_entropy": 7.5})
    assert report is not None
    assert report.attack_category == "Botnet_C2"
    assert report.threat_score >= 90

def test_cti_transfer_correlation():
    init_db()
    transfer = CTITransferModel()
    
    cti_rep = CTIReport(
        ioc_value="198.51.100.42",
        ioc_type="IP",
        threat_score=95,
        threat_level="Critical",
        malware_family="CobaltStrike",
        attack_category="Botnet_C2",
        confidence=0.96,
        cve_list=[],
        sources=["AlienVault OTX"],
        description="Active C2 beacon",
        tags=["c2"],
        first_seen="2026-01-01T00:00:00Z",
        last_seen="2026-01-01T00:00:00Z"
    )

    flow_data = {
        "features": {
            "payload_entropy": 7.6,
            "down_up_ratio": 2.5
        },
        "src_ip": "198.51.100.42"
    }

    result = transfer.process_and_transfer("TEST-FLOW-01", flow_data, cti_rep)
    assert result.is_validated is True
    assert result.correlation_confidence >= 0.75
    assert result.assigned_label == "Botnet_C2"
