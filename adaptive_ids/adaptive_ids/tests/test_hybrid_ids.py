import pytest
import numpy as np
import pandas as pd
from app.core.hybrid_ids import HybridIDS
from app.core.traffic_generator import generate_base_dataset, generate_flow_sample

def test_hybrid_ids_training_and_prediction():
    np.random.seed(42)
    ids = HybridIDS()
    df = generate_base_dataset(n_samples=80)
    
    metrics = ids.train_initial(df, target_col="label_id")
    assert ids.is_trained is True
    assert metrics["accuracy"] > 0.70
    assert metrics["f1_score"] > 0.70

    # Test benign flow prediction
    benign_flow = generate_flow_sample("benign")
    pred = ids.predict_single(benign_flow["features"])
    assert "predicted_class" in pred
    assert "confidence" in pred
    assert "is_anomaly" in pred
    assert "anomaly_score" in pred

    # Test DoS flow prediction
    dos_flow = generate_flow_sample("dos")
    dos_pred = ids.predict_single(dos_flow["features"])
    assert dos_pred["predicted_class"] in ["DoS_DDoS", "Unknown", "PortScan"]
