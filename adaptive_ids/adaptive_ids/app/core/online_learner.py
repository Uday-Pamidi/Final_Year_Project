import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.config import (
    FLOW_FEATURES,
    ATTACK_CLASS_TO_ID,
    ATTACK_CLASSES,
    REPLAY_BUFFER_SIZE
)
from app.models.database import (
    get_unincorporated_cti_samples,
    mark_cti_samples_incorporated,
    save_model_version,
    get_model_versions
)

class OnlineLearner:
    """
    Online & Incremental Model Update Manager:
    Manages continuous model evolution, CTI validated sample incorporation,
    replay buffer maintenance (preventing catastrophic forgetting),
    model versioning, and post-update validation.
    """

    def __init__(self, hybrid_ids, shap_explainer, drift_detector, replay_df: Optional[pd.DataFrame] = None):
        self.hybrid_ids = hybrid_ids
        self.shap_explainer = shap_explainer
        self.drift_detector = drift_detector
        self.replay_df = replay_df if replay_df is not None else pd.DataFrame()
        self.version_counter = 1

    def set_replay_buffer(self, df: pd.DataFrame):
        self.replay_df = df.copy()

    def update_replay_buffer(self, new_df: pd.DataFrame):
        if self.replay_df.empty:
            self.replay_df = new_df.copy()
        else:
            self.replay_df = pd.concat([self.replay_df, new_df], ignore_index=True)
            if len(self.replay_df) > REPLAY_BUFFER_SIZE:
                # Keep stratified or recent sample
                self.replay_df = self.replay_df.sample(n=REPLAY_BUFFER_SIZE, random_state=42)

    def trigger_dynamic_update(self, reason: str = "CTI Validated Buffer Threshold Reached") -> Dict[str, Any]:
        """
        Executes dynamic model update:
        1. Gathers pending validated CTI samples.
        2. Combines with historical replay memory.
        3. Updates XGBoost & Isolation Forest.
        4. Updates model version (e.g. v1.1, v1.2).
        5. Updates SHAP explainer and Drift Detector baseline.
        """
        unincorporated = get_unincorporated_cti_samples()
        
        if not unincorporated and self.replay_df.empty:
            return {
                "success": False,
                "message": "No new validated CTI samples or baseline data available for retraining.",
                "old_version": self.hybrid_ids.version,
                "new_version": self.hybrid_ids.version,
                "samples_added": 0,
                "before_metrics": {},
                "after_metrics": {}
            }

        # Convert CTI samples to DataFrame
        new_records = []
        sample_ids = []
        for sample in unincorporated:
            row = dict(sample["features"])
            row["label_id"] = int(sample["validated_class_id"])
            row["label_name"] = sample["validated_label"]
            new_records.append(row)
            sample_ids.append(sample["id"])

        if new_records:
            new_df = pd.DataFrame(new_records)
        else:
            # Synthetic adaptive update on replay buffer if manual update forced
            new_df = self.replay_df.sample(min(30, len(self.replay_df)), replace=True)

        old_version = self.hybrid_ids.version
        self.version_counter += 1
        new_version = f"v1.{self.version_counter - 1}"

        # Execute incremental retrain in HybridIDS
        replay_sample = self.replay_df.sample(min(len(self.replay_df), 300), random_state=42) if not self.replay_df.empty else new_df
        update_result = self.hybrid_ids.retrain_incremental(
            new_samples_df=new_df,
            replay_df=replay_sample,
            new_version_str=new_version
        )

        # Mark incorporated in DB
        mark_cti_samples_incorporated(sample_ids)

        # Add new samples to replay buffer
        self.update_replay_buffer(new_df)

        # Update SHAP TreeExplainer with new XGBoost booster
        self.shap_explainer.update_model(self.hybrid_ids.xgb_model)

        # Update Drift Detector baseline window to acknowledge shifted distribution
        self.drift_detector.update_baseline_with_active()

        # Save model version metadata to registry
        after_m = update_result["after_metrics"]
        save_model_version({
            "version": new_version,
            "timestamp": datetime.utcnow().isoformat(),
            "trigger_reason": reason,
            "total_training_samples": update_result["samples_trained"],
            "cti_samples_incorporated": len(new_records),
            "accuracy": after_m["accuracy"],
            "precision": after_m["precision"],
            "recall": after_m["recall"],
            "f1_score": after_m["f1_score"]
        })

        return {
            "success": True,
            "old_version": old_version,
            "new_version": new_version,
            "trigger_reason": reason,
            "samples_added": len(new_records),
            "before_metrics": update_result["before_metrics"],
            "after_metrics": update_result["after_metrics"],
            "message": f"Successfully updated model to {new_version}. Incorporated {len(new_records)} CTI-validated samples."
        }
