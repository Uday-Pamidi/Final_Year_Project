import numpy as np
import pandas as pd
from scipy import stats
from datetime import datetime
from typing import Dict, Any, List, Tuple
from collections import deque

from app.config import (
    FLOW_FEATURES,
    DRIFT_WINDOW_SIZE,
    REFERENCE_BASELINE_SIZE,
    KS_ALPHA_THRESHOLD,
    PSI_WARNING_THRESHOLD,
    PSI_DRIFT_THRESHOLD
)
from app.models.schemas import FeatureDriftMetric, DriftAnalysisResult
from app.models.database import log_drift

class ADWINDriftDetector:
    """
    Adaptive Windowing (ADWIN) implementation for streaming error / anomaly rate tracking.
    Maintains a sliding window and tests sub-window cuts using Hoeffding bounds.
    """
    def __init__(self, delta: float = 0.002, max_size: int = 250):
        self.delta = delta
        self.max_size = max_size
        self.window = deque(maxlen=max_size)
        self.drift_detected = False

    def add_element(self, value: float) -> bool:
        self.window.append(value)
        if len(self.window) < 30:
            self.drift_detected = False
            return False

        # Evaluate cut points
        n = len(self.window)
        arr = np.array(self.window)
        self.drift_detected = False

        # Test middle cut
        split_idx = n // 2
        w0 = arr[:split_idx]
        w1 = arr[split_idx:]

        n0 = len(w0)
        n1 = len(w1)
        m = 1.0 / (1.0 / n0 + 1.0 / n1)

        # Hoeffding bound eps_cut
        eps_cut = np.sqrt((1.0 / (2.0 * m)) * np.log(4.0 * n / self.delta))
        diff = abs(np.mean(w0) - np.mean(w1))

        if diff > eps_cut:
            self.drift_detected = True
            # Shrink window
            for _ in range(n0 // 2):
                if self.window:
                    self.window.popleft()
            return True

        return False

class ConceptDriftDetector:
    """
    Concept Drift Detection Engine:
    - Monitors incoming network flows using a sliding window.
    - Computes two-sample Kolmogorov-Smirnov (KS) test between reference baseline and active window.
    - Computes Population Stability Index (PSI).
    - Tracks anomaly rate drift using ADWIN.
    """

    def __init__(
        self,
        window_size: int = DRIFT_WINDOW_SIZE,
        baseline_size: int = REFERENCE_BASELINE_SIZE
    ):
        self.window_size = window_size
        self.baseline_size = baseline_size
        self.features = FLOW_FEATURES
        
        # Sliding buffer for incoming traffic
        self.active_window: deque = deque(maxlen=window_size)
        
        # Reference baseline buffer (trained model distribution)
        self.baseline_window: deque = deque(maxlen=baseline_size)

        # ADWIN instance for anomaly rate
        self.adwin = ADWINDriftDetector(delta=0.01, max_size=window_size)

    def set_reference_baseline(self, df: pd.DataFrame):
        """Initializes the baseline reference distribution from base dataset."""
        self.baseline_window.clear()
        records = df[self.features].to_dict(orient="records")
        for r in records[:self.baseline_size]:
            self.baseline_window.append(r)

    def add_flow(self, flow_features: Dict[str, Any], is_anomaly_or_uncertain: bool = False) -> bool:
        """Adds incoming flow to sliding window and checks ADWIN."""
        self.active_window.append({k: float(flow_features.get(k, 0.0)) for k in self.features})
        adwin_signal = self.adwin.add_element(1.0 if is_anomaly_or_uncertain else 0.0)
        return adwin_signal

    def calculate_psi(self, baseline_arr: np.ndarray, active_arr: np.ndarray, bins: int = 8) -> float:
        """Calculates Population Stability Index between two 1D distributions."""
        try:
            # Drop NaN or inf
            b = baseline_arr[np.isfinite(baseline_arr)]
            a = active_arr[np.isfinite(active_arr)]

            if len(b) < 10 or len(a) < 10:
                return 0.0

            # Quantile-based bin edges from baseline
            percentiles = np.linspace(0, 100, bins + 1)
            bin_edges = np.percentile(b, percentiles)
            bin_edges = np.unique(bin_edges)
            if len(bin_edges) < 3:
                return 0.0

            b_counts, _ = np.histogram(b, bins=bin_edges)
            a_counts, _ = np.histogram(a, bins=bin_edges)

            # Avoid zero division
            b_pct = (b_counts + 1e-4) / (len(b) + 1e-4 * len(b_counts))
            a_pct = (a_counts + 1e-4) / (len(a) + 1e-4 * len(a_counts))

            psi = np.sum((a_pct - b_pct) * np.log(a_pct / b_pct))
            return float(np.clip(psi, 0.0, 5.0))
        except Exception:
            return 0.0

    def analyze_drift(self) -> DriftAnalysisResult:
        """
        Runs comprehensive drift analysis:
        - Evaluates KS test & PSI across each network feature.
        - Evaluates ADWIN anomaly rate signal.
        - Summarizes overall drift state.
        """
        active_len = len(self.active_window)
        base_len = len(self.baseline_window)

        if active_len < 25 or base_len < 25:
            # Insufficient samples yet
            return DriftAnalysisResult(
                overall_status="STABLE",
                drift_detected=False,
                active_window_size=active_len,
                baseline_window_size=base_len,
                drifting_features=[],
                metrics=[],
                adwin_drift_signal=False,
                timestamp=datetime.utcnow().isoformat()
            )

        active_df = pd.DataFrame(list(self.active_window))
        base_df = pd.DataFrame(list(self.baseline_window))

        metrics: List[FeatureDriftMetric] = []
        drifting_features: List[str] = []
        ks_stats = []
        p_values = []

        for feat in self.features:
            base_col = base_df[feat].values
            active_col = active_df[feat].values

            # Two-sample Kolmogorov-Smirnov test
            try:
                ks_res = stats.ks_2samp(base_col, active_col)
                ks_stat = round(float(ks_res.statistic), 4)
                p_val = round(float(ks_res.pvalue), 4)
            except Exception:
                ks_stat, p_val = 0.0, 1.0

            psi = round(self.calculate_psi(base_col, active_col), 4)

            # Drift rule: KS p-value < 0.05 AND (KS statistic > 0.18 OR PSI > 0.25)
            is_feature_drift = (p_val < KS_ALPHA_THRESHOLD and (ks_stat > 0.18 or psi >= PSI_DRIFT_THRESHOLD))
            
            if is_feature_drift:
                status_str = "DRIFT_DETECTED"
                drifting_features.append(feat)
            elif p_val < KS_ALPHA_THRESHOLD or psi >= PSI_WARNING_THRESHOLD:
                status_str = "WARNING"
            else:
                status_str = "STABLE"

            metrics.append(FeatureDriftMetric(
                feature=feat,
                ks_statistic=ks_stat,
                p_value=p_val,
                psi_score=psi,
                is_drift=is_feature_drift,
                status=status_str
            ))

            ks_stats.append(ks_stat)
            p_values.append(p_val)

        # Overall Status Determination
        adwin_signal = self.adwin.drift_detected
        num_drifting = len(drifting_features)

        if num_drifting >= 2 or (num_drifting >= 1 and adwin_signal):
            overall_status = "DRIFT_DETECTED"
            drift_detected = True
        elif num_drifting == 1 or adwin_signal or any(m.status == "WARNING" for m in metrics):
            overall_status = "WARNING"
            drift_detected = False
        else:
            overall_status = "STABLE"
            drift_detected = False

        avg_ks = round(float(np.mean(ks_stats)), 4) if ks_stats else 0.0
        min_p = round(float(np.min(p_values)), 4) if p_values else 1.0

        # Log to database
        log_drift({
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": overall_status,
            "drift_detected": drift_detected,
            "drifting_features": drifting_features,
            "avg_ks_statistic": avg_ks,
            "min_p_value": min_p,
            "window_size": active_len
        })

        return DriftAnalysisResult(
            overall_status=overall_status,
            drift_detected=drift_detected,
            active_window_size=active_len,
            baseline_window_size=base_len,
            drifting_features=drifting_features,
            metrics=metrics,
            adwin_drift_signal=adwin_signal,
            timestamp=datetime.utcnow().isoformat()
        )

    def update_baseline_with_active(self):
        """Updates baseline with current active window following dynamic retrain."""
        for item in self.active_window:
            self.baseline_window.append(item)
        self.active_window.clear()
        self.adwin.drift_detected = False
