import pandas as pd
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List

from app.core.ids_service import IDSService
from app.config import DATA_DIR

router = APIRouter(prefix="/api/explain", tags=["Explainable AI (SHAP)"])

@router.get("/flow/{flow_id}")
def explain_specific_flow(flow_id: str):
    service = IDSService.get_instance()
    res = service.explain_flow(flow_id)
    if not res:
        raise HTTPException(status_code=404, detail="Flow not found or features unavailable")
    return res

@router.get("/global")
def get_global_importance(samples: int = 100):
    service = IDSService.get_instance()
    csv_path = DATA_DIR / "base_traffic_sample.csv"
    if csv_path.exists():
        df = pd.read_csv(csv_path)
    else:
        df = service.online_learner.replay_df

    importance = service.shap_explainer.get_global_importance(df, num_samples=samples)
    return {
        "model_version": service.hybrid_ids.version,
        "sample_size": min(len(df), samples),
        "rankings": importance
    }
