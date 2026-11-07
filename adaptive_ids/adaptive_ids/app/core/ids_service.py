import os
import pandas as pd
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.config import (
    DATA_DIR,
    CTI_BUFFER_RETRAIN_TRIGGER,
    FLOW_FEATURES
)
from app.models.database import (
    init_db,
    save_flow,
    save_model_version,
    get_model_versions,
    get_active_model_version,
    get_unincorporated_cti_samples,
    get_recent_flows,
    get_dashboard_stats
)
from app.core.hybrid_ids import HybridIDS
from app.core.cti_engine import CTIEngine
from app.core.cti_transfer import CTITransferModel
from app.core.drift_detector import ConceptDriftDetector
from app.core.shap_explainer import SHAPExplainer
from app.core.online_learner import OnlineLearner
from app.core.traffic_generator import generate_base_dataset, generate_flow_sample

class IDSService:
    _instance = None

    def __init__(self):
        self.hybrid_ids = HybridIDS()
        self.cti_engine = CTIEngine()
        self.cti_transfer = CTITransferModel()
        self.drift_detector = ConceptDriftDetector()
        self.shap_explainer = None
        self.online_learner = None
        self.is_initialized = False

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = IDSService()
        return cls._instance

    def initialize(self):
        if self.is_initialized:
            return

        init_db()

        # Check for pre-existing dataset or generate baseline
        csv_path = DATA_DIR / "base_traffic_sample.csv"
        if not csv_path.exists():
            print("Generating initial base training dataset...")
            base_df = generate_base_dataset(n_samples=600)
        else:
            base_df = pd.read_csv(csv_path)

        # Check if saved models exist; if not, train initial model
        loaded = self.hybrid_ids.load_models()
        if not loaded:
            print("Training initial Hybrid IDS (XGBoost + Isolation Forest)...")
            metrics = self.hybrid_ids.train_initial(base_df, target_col="label_id")
            
            # Save base version v1.0
            save_model_version({
                "version": "v1.0",
                "timestamp": datetime.utcnow().isoformat(),
                "trigger_reason": "Initial Deployment Baseline Training",
                "total_training_samples": len(base_df),
                "cti_samples_incorporated": 0,
                "accuracy": metrics["accuracy"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1_score": metrics["f1_score"]
            })
        else:
            print(f"Loaded existing model {self.hybrid_ids.version}")

        # Set reference baseline in drift detector
        self.drift_detector.set_reference_baseline(base_df)

        # Initialize SHAP explainer
        self.shap_explainer = SHAPExplainer(self.hybrid_ids.xgb_model)

        # Initialize Online Learner
        self.online_learner = OnlineLearner(
            hybrid_ids=self.hybrid_ids,
            shap_explainer=self.shap_explainer,
            drift_detector=self.drift_detector,
            replay_df=base_df
        )

        self.is_initialized = True
        print("Adaptive IDS System successfully initialized and ready.")

    def process_flow(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        End-to-end DICI flow analysis pipeline:
        1. Hybrid Classification & Anomaly Detection
        2. Database persistence
        3. Concept Drift sliding window ingestion
        4. IoC extraction & CTI Transfer Model Correlation (if uncertain/anomalous)
        5. Check automated dynamic retraining conditions
        """
        features = flow_data.get("features", {})
        flow_id = flow_data.get("id", f"FL-{datetime.utcnow().timestamp()}")

        # 1. Hybrid IDS Prediction
        pred = self.hybrid_ids.predict_single(features)

        # 2. Add to drift detector sliding window
        self.drift_detector.add_flow(features, is_anomaly_or_uncertain=pred["is_uncertain"])

        # 3. Handle CTI query & Transfer Model if uncertain or anomalous
        cti_report = None
        transfer_result = None
        if pred["requires_cti"] and pred["ioc_extracted"]:
            cti_report = self.cti_engine.query_ioc(pred["ioc_extracted"])
            transfer_result = self.cti_transfer.process_and_transfer(
                flow_id=flow_id,
                flow_data=flow_data,
                cti_report=cti_report
            )

        # 4. Save flow in database
        save_flow({
            "id": flow_id,
            "timestamp": flow_data.get("timestamp", datetime.utcnow().isoformat()),
            "src_ip": flow_data.get("src_ip", "192.168.1.100"),
            "dst_ip": flow_data.get("dst_ip", "10.0.0.1"),
            "src_port": flow_data.get("src_port", 50000),
            "dst_port": flow_data.get("dst_port", 80),
            "protocol": flow_data.get("protocol", "TCP"),
            "features": features,
            "predicted_class": pred["predicted_class"],
            "predicted_class_id": pred["predicted_class_id"],
            "confidence": pred["confidence"],
            "is_anomaly": pred["is_anomaly"],
            "anomaly_score": pred["anomaly_score"],
            "is_uncertain": pred["is_uncertain"],
            "requires_cti": pred["requires_cti"],
            "ground_truth": flow_data.get("ground_truth"),
            "cti_matched": bool(cti_report is not None),
            "cti_threat_score": cti_report.threat_score if cti_report else 0,
            "status": pred["status"]
        })

        # 5. Check if CTI buffer triggers automated update
        unincorporated_count = self.cti_transfer.get_pending_sample_count()
        auto_retrain_triggered = False
        retrain_info = None

        if unincorporated_count >= CTI_BUFFER_RETRAIN_TRIGGER:
            print(f"CTI Buffer threshold reached ({unincorporated_count} samples). Triggering dynamic update...")
            retrain_info = self.online_learner.trigger_dynamic_update(
                reason=f"Automated Trigger: CTI Buffer reached {unincorporated_count} samples"
            )
            auto_retrain_triggered = True

        to_dict = lambda obj: obj.model_dump() if hasattr(obj, "model_dump") else obj.dict()

        return {
            "flow_id": flow_id,
            "timestamp": flow_data.get("timestamp", datetime.utcnow().isoformat()),
            "prediction": pred,
            "cti_report": to_dict(cti_report) if cti_report else None,
            "transfer_result": to_dict(transfer_result) if transfer_result else None,
            "unincorporated_cti_count": unincorporated_count,
            "auto_retrain_triggered": auto_retrain_triggered,
            "retrain_info": retrain_info
        }

    def explain_flow(self, flow_id: str) -> Optional[Dict[str, Any]]:
        recent = get_recent_flows(limit=100)
        target = next((f for f in recent if f["id"] == flow_id), None)
        if not target:
            return None

        features = target.get("features", {})
        pred_label = target.get("predicted_class", "Benign")
        pred_id = int(target.get("predicted_class_id", 0))
        conf = float(target.get("confidence", 0.0))

        explanation = self.shap_explainer.explain_flow(
            flow_features=features,
            predicted_class_id=pred_id,
            predicted_class_name=pred_label,
            confidence=conf
        )

        return {
            "flow_id": flow_id,
            "timestamp": target.get("timestamp"),
            "src_ip": target.get("src_ip"),
            "dst_ip": target.get("dst_ip"),
            "dst_port": target.get("dst_port"),
            "predicted_label": pred_label,
            "confidence": conf,
            "is_anomaly": target.get("is_anomaly"),
            "status": target.get("status"),
            "base_value": explanation["base_value"],
            "feature_contributions": explanation["feature_contributions"],
            "analyst_summary": explanation["analyst_summary"]
        }
