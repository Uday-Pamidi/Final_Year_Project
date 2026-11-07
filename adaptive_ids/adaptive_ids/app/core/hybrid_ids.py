import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, List, Optional
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from app.config import (
    FLOW_FEATURES,
    ATTACK_CLASSES,
    ATTACK_CLASS_TO_ID,
    CONFIDENCE_THRESHOLD,
    ISOLATION_FOREST_CONTAMINATION,
    MODEL_DIR
)

class HybridIDS:
    def __init__(self):
        self.features = FLOW_FEATURES
        self.num_classes = len(ATTACK_CLASSES)
        self.scaler = StandardScaler()
        
        # XGBoost Supervised Classifier
        self.xgb_model = xgb.XGBClassifier(
            n_estimators=60,
            max_depth=5,
            learning_rate=0.1,
            objective="multi:softprob",
            num_class=self.num_classes,
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=2
        )
        
        # Isolation Forest Unsupervised Anomaly Detector
        self.iso_forest = IsolationForest(
            n_estimators=75,
            contamination=ISOLATION_FOREST_CONTAMINATION,
            random_state=42,
            n_jobs=2
        )
        
        self.is_trained = False
        self.version = "v1.0"

    def feature_dict_to_array(self, feat_dict: Dict[str, Any]) -> np.ndarray:
        vec = []
        for feat in self.features:
            val = float(feat_dict.get(feat, 0.0))
            vec.append(val)
        return np.array(vec, dtype=np.float32).reshape(1, -1)

    def dataframe_to_matrix(self, df: pd.DataFrame) -> np.ndarray:
        return df[self.features].values.astype(np.float32)

    def train_initial(self, df: pd.DataFrame, target_col: str = "label_id") -> Dict[str, float]:
        X = self.dataframe_to_matrix(df)
        y = df[target_col].values.astype(int)

        # Fit Scaler
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)

        # Fit XGBoost Classifier
        self.xgb_model.fit(X, y)

        # Fit Isolation Forest on Benign flows (label_id == 0)
        benign_mask = (y == 0)
        if np.sum(benign_mask) > 20:
            self.iso_forest.fit(X[benign_mask])
        else:
            self.iso_forest.fit(X)

        self.is_trained = True
        self.version = "v1.0"

        # Calculate metrics
        y_pred = self.xgb_model.predict(X)
        acc = float(accuracy_score(y, y_pred))
        p, r, f1, _ = precision_recall_fscore_support(y, y_pred, average="weighted", zero_division=0)

        metrics = {
            "accuracy": round(acc, 4),
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1_score": round(float(f1), 4)
        }
        self.save_models()
        return metrics

    def predict_single(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        DICI Hybrid Pipeline:
        1. XGBoost predicts class probabilities.
        2. Isolation Forest evaluates anomaly score.
        3. Identifies whether flow is anomalous or low confidence (requires CTI).
        4. Extracts candidate IoCs.
        """
        if not self.is_trained:
            # If not yet trained, return fallback
            return {
                "predicted_class": "Benign",
                "predicted_class_id": 0,
                "confidence": 0.5,
                "probabilities": {name: 0.16 for name in ATTACK_CLASSES.values()},
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "is_uncertain": True,
                "requires_cti": True,
                "status": "Untrained Model",
                "ioc_extracted": None
            }

        X = self.feature_dict_to_array(flow_dict)
        
        # XGBoost Prediction
        probs = self.xgb_model.predict_proba(X)[0]
        pred_class_id = int(np.argmax(probs))
        confidence = float(np.max(probs))
        pred_class_name = ATTACK_CLASSES.get(pred_class_id, "Unknown")
        
        prob_dict = {
            ATTACK_CLASSES[i]: round(float(probs[i]), 4)
            for i in range(len(probs))
        }

        # Isolation Forest Anomaly Detection
        # decision_function: lower means more anomalous (negative = anomaly)
        raw_score = float(self.iso_forest.decision_function(X)[0])
        # predict: +1 for normal, -1 for anomaly
        iso_pred = int(self.iso_forest.predict(X)[0])
        is_anomaly = bool(iso_pred == -1 or raw_score < -0.05)

        # Anomaly score normalized roughly to [0, 1] where 1 is highly anomalous
        normalized_anomaly_score = round(float(1.0 / (1.0 + np.exp(raw_score * 4.0))), 4)

        # Uncertainty condition from base paper:
        # Confidence below tau (CONFIDENCE_THRESHOLD = 0.70) OR Anomaly flagged by Isolation Forest
        is_low_confidence = (confidence < CONFIDENCE_THRESHOLD)
        is_uncertain = is_low_confidence or is_anomaly
        requires_cti = is_uncertain

        # Determine flow status tag
        if is_anomaly and is_low_confidence:
            status = "Zero-Day Candidate / High Anomaly"
        elif is_anomaly:
            status = "Structural Anomaly"
        elif is_low_confidence:
            status = "Low Confidence Prediction"
        elif pred_class_name != "Benign":
            status = f"Known Threat ({pred_class_name})"
        else:
            status = "Normal Benign Traffic"

        # IoC Extraction candidate
        ioc_extracted = None
        if requires_cti or pred_class_name != "Benign":
            src_ip = flow_dict.get("src_ip", "192.168.1.100")
            dst_ip = flow_dict.get("dst_ip", "10.0.0.1")
            dst_port = int(flow_dict.get("dst_port", 80))
            proto = flow_dict.get("protocol", "TCP")
            entropy = float(flow_dict.get("payload_entropy", 3.0))
            flow_hash = f"FLOW-{abs(hash((src_ip, dst_ip, dst_port, proto))):x}"[:12]
            
            flags = []
            if flow_dict.get("syn_flag_count", 0) > 0: flags.append("SYN")
            if flow_dict.get("fin_flag_count", 0) > 0: flags.append("FIN")
            if flow_dict.get("rst_flag_count", 0) > 0: flags.append("RST")
            if flow_dict.get("psh_flag_count", 0) > 0: flags.append("PSH")
            if flow_dict.get("ack_flag_count", 0) > 0: flags.append("ACK")
            flag_sig = "-".join(flags) if flags else "NONE"

            ioc_extracted = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "flow_hash": flow_hash,
                "payload_entropy": entropy,
                "flag_signature": flag_sig
            }

        return {
            "predicted_class": pred_class_name,
            "predicted_class_id": pred_class_id,
            "confidence": round(confidence, 4),
            "probabilities": prob_dict,
            "is_anomaly": is_anomaly,
            "anomaly_score": normalized_anomaly_score,
            "is_uncertain": is_uncertain,
            "requires_cti": requires_cti,
            "status": status,
            "ioc_extracted": ioc_extracted
        }

    def retrain_incremental(
        self,
        new_samples_df: pd.DataFrame,
        replay_df: pd.DataFrame,
        new_version_str: str
    ) -> Dict[str, Any]:
        """
        Incremental learning & dynamic model update:
        Combines new validated CTI samples with representative historical replay data.
        Updates XGBoost boosting trees and refits Isolation Forest to adapt to emerging threats.
        """
        combined_df = pd.concat([replay_df, new_samples_df], ignore_index=True)
        X_comb = self.dataframe_to_matrix(combined_df)
        y_comb = combined_df["label_id"].values.astype(int)

        # Baseline evaluation before retrain on combined distribution
        X_test = X_comb
        y_test = y_comb
        y_pred_before = self.xgb_model.predict(X_test)
        acc_before = float(accuracy_score(y_test, y_pred_before))
        p_b, r_b, f1_b, _ = precision_recall_fscore_support(y_test, y_pred_before, average="weighted", zero_division=0)
        before_metrics = {
            "accuracy": round(acc_before, 4),
            "precision": round(float(p_b), 4),
            "recall": round(float(r_b), 4),
            "f1_score": round(float(f1_b), 4)
        }

        # Train new XGBoost model with warm-start / incremental boosting or fit on combined updated distribution
        current_trees = self.xgb_model.n_estimators
        new_xgb = xgb.XGBClassifier(
            n_estimators=current_trees + 15,
            max_depth=5,
            learning_rate=0.08,
            objective="multi:softprob",
            num_class=self.num_classes,
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=2
        )
        new_xgb.fit(X_comb, y_comb)
        self.xgb_model = new_xgb

        # Dynamic refit of Isolation Forest with updated benign/baseline data
        benign_flows = X_comb[y_comb == 0]
        if len(benign_flows) > 20:
            self.iso_forest.fit(benign_flows)
        else:
            self.iso_forest.fit(X_comb)

        self.version = new_version_str
        self.save_models()

        # After metrics
        y_pred_after = self.xgb_model.predict(X_test)
        acc_after = float(accuracy_score(y_test, y_pred_after))
        p_a, r_a, f1_a, _ = precision_recall_fscore_support(y_test, y_pred_after, average="weighted", zero_division=0)
        after_metrics = {
            "accuracy": round(acc_after, 4),
            "precision": round(float(p_a), 4),
            "recall": round(float(r_a), 4),
            "f1_score": round(float(f1_a), 4)
        }

        return {
            "before_metrics": before_metrics,
            "after_metrics": after_metrics,
            "samples_trained": len(combined_df),
            "new_samples_count": len(new_samples_df)
        }

    def save_models(self):
        xgb_path = MODEL_DIR / "xgb_model.joblib"
        iso_path = MODEL_DIR / "iso_forest.joblib"
        meta_path = MODEL_DIR / "model_meta.joblib"

        joblib.dump(self.xgb_model, xgb_path)
        joblib.dump(self.iso_forest, iso_path)
        joblib.dump({
            "version": self.version,
            "features": self.features,
            "is_trained": self.is_trained
        }, meta_path)

    def load_models(self) -> bool:
        xgb_path = MODEL_DIR / "xgb_model.joblib"
        iso_path = MODEL_DIR / "iso_forest.joblib"
        meta_path = MODEL_DIR / "model_meta.joblib"

        if xgb_path.exists() and iso_path.exists() and meta_path.exists():
            try:
                self.xgb_model = joblib.load(xgb_path)
                self.iso_forest = joblib.load(iso_path)
                meta = joblib.load(meta_path)
                self.version = meta.get("version", "v1.0")
                self.is_trained = meta.get("is_trained", True)
                return True
            except Exception as e:
                print(f"Error loading models: {e}")
                return False
        return False
