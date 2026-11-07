from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any, List

from app.core.ids_service import IDSService
from app.models.database import (
    get_model_versions,
    get_active_model_version
)

router = APIRouter(prefix="/api/models", tags=["Model Governance"])

class RetrainTriggerRequest(BaseModel):
    reason: str = "SOC Manual Adaptation Trigger"

@router.get("/versions")
def list_model_versions():
    return get_model_versions()

@router.get("/active")
def get_current_model_info():
    service = IDSService.get_instance()
    active_db = get_active_model_version()
    return {
        "version": service.hybrid_ids.version,
        "is_trained": service.hybrid_ids.is_trained,
        "features_count": len(service.hybrid_ids.features),
        "num_classes": service.hybrid_ids.num_classes,
        "db_record": active_db
    }

@router.post("/retrain")
def trigger_retrain(req: RetrainTriggerRequest):
    service = IDSService.get_instance()
    return service.online_learner.trigger_dynamic_update(reason=req.reason)
