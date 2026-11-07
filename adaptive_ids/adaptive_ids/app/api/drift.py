from fastapi import APIRouter
from app.core.ids_service import IDSService
from app.models.database import get_recent_drift_logs

router = APIRouter(prefix="/api/drift", tags=["Concept Drift"])

@router.get("/status")
def get_drift_status():
    service = IDSService.get_instance()
    analysis = service.drift_detector.analyze_drift()
    to_dict = lambda obj: obj.model_dump() if hasattr(obj, "model_dump") else obj.dict()
    return to_dict(analysis)

@router.get("/history")
def get_drift_history(limit: int = 15):
    return get_recent_drift_logs(limit=limit)

@router.post("/trigger_retrain")
def manual_trigger_retrain():
    service = IDSService.get_instance()
    res = service.online_learner.trigger_dynamic_update(
        reason="Manual SOC Analyst Trigger via Drift Dashboard"
    )
    return res
