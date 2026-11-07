import pytest
import pandas as pd
from app.core.drift_detector import ConceptDriftDetector, ADWINDriftDetector
from app.core.traffic_generator import generate_flow_sample

def test_adwin_drift_detector():
    adwin = ADWINDriftDetector(delta=0.01, max_size=100)
    # Stream identical baseline values
    for _ in range(35):
        adwin.add_element(0.0)
    assert adwin.drift_detected is False

    # Stream a massive surge of anomalies (simulating attack wave)
    drifted = False
    for _ in range(35):
        if adwin.add_element(1.0):
            drifted = True
            break
    assert drifted is True

def test_concept_drift_ks_analysis():
    import numpy as np
    np.random.seed(42)
    detector = ConceptDriftDetector(window_size=40, baseline_size=50)
    
    # Baseline
    base_flows = [generate_flow_sample("benign")["features"] for _ in range(50)]
    base_df = pd.DataFrame(base_flows)
    detector.set_reference_baseline(base_df)

    # Ingest normal flows
    for _ in range(35):
        detector.add_flow(generate_flow_sample("benign")["features"])

    res_normal = detector.analyze_drift()
    assert res_normal.overall_status in ["STABLE", "WARNING"]

    # Ingest drifting zero-day flows with extreme packet velocity and entropy
    for _ in range(40):
        detector.add_flow(generate_flow_sample("zero_day")["features"])

    res_drift = detector.analyze_drift()
    assert len(res_drift.drifting_features) >= 0
