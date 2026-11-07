from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from pydantic import BaseModel

from app.core.ids_service import IDSService
from app.models.database import (
    get_recent_ioc_records,
    get_unincorporated_cti_samples
)

router = APIRouter(prefix="/api/cti", tags=["Cyber Threat Intelligence"])

class CTIQueryRequest(BaseModel):
    ioc_value: str
    ioc_type: str = "IP"
    payload_entropy: float = 3.5
    dst_port: int = 80

class SignatureCreateRequest(BaseModel):
    ioc_value: str
    ioc_type: str = "IP"
    threat_score: int
    threat_level: str
    malware_family: str
    attack_category: str
    confidence: float
    description: str
    cve_list: List[str] = []
    sources: List[str] = ["Manual SOC Analyst Submission"]

@router.get("/signatures")
def list_signatures():
    service = IDSService.get_instance()
    return service.cti_engine.get_all_signatures()

@router.post("/query")
def query_threat_intel(req: CTIQueryRequest):
    service = IDSService.get_instance()
    ioc_dict = {
        "src_ip": req.ioc_value if req.ioc_type == "IP" else "",
        "dst_port": req.dst_port,
        "payload_entropy": req.payload_entropy
    }
    res = service.cti_engine.query_ioc(ioc_dict)
    to_dict = lambda obj: obj.model_dump() if hasattr(obj, "model_dump") else obj.dict()
    if not res:
        return {"found": False, "message": "No match found in CTI repositories"}
    return {"found": True, "report": to_dict(res)}

@router.post("/add_signature")
def add_signature(req: SignatureCreateRequest):
    service = IDSService.get_instance()
    sig = {
        "ioc_value": req.ioc_value,
        "ioc_type": req.ioc_type,
        "threat_score": req.threat_score,
        "threat_level": req.threat_level,
        "malware_family": req.malware_family,
        "attack_category": req.attack_category,
        "confidence": req.confidence,
        "cve_list": req.cve_list,
        "sources": req.sources,
        "description": req.description,
        "tags": [req.malware_family.lower(), req.attack_category.lower(), "analyst-curated"],
        "first_seen": __import__("datetime").datetime.utcnow().isoformat(),
        "last_seen": __import__("datetime").datetime.utcnow().isoformat()
    }
    service.cti_engine.add_signature(sig)
    return {"success": True, "signature": sig}

@router.get("/ioc_records")
def get_ioc_records(limit: int = 50):
    return get_recent_ioc_records(limit=limit)

@router.get("/validated_buffer")
def get_validated_buffer():
    samples = get_unincorporated_cti_samples()
    return {
        "pending_count": len(samples),
        "threshold": 25,
        "samples": samples[:25]
    }
