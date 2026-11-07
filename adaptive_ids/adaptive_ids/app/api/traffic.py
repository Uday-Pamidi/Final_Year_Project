import io
import pandas as pd
from fastapi import APIRouter, HTTPException, UploadFile, File
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.models.schemas import NetworkFlowIn, SimulationBatchRequest
from app.core.ids_service import IDSService
from app.core.traffic_generator import generate_flow_sample
from app.models.database import get_recent_flows, get_flow_by_id

router = APIRouter(prefix="/api/traffic", tags=["Network Traffic"])

@router.post("/ingest")
def ingest_flow(flow: NetworkFlowIn):
    service = IDSService.get_instance()
    flow_dict = {
        "id": f"FL-{datetime.utcnow().strftime('%H%M%S')}-{abs(hash(flow.src_ip + str(flow.src_port)) % 10000)}",
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "ground_truth": flow.ground_truth,
        "features": {
            "flow_duration": flow.flow_duration,
            "total_fwd_packets": flow.total_fwd_packets,
            "total_bwd_packets": flow.total_bwd_packets,
            "total_fwd_bytes": flow.total_fwd_bytes,
            "total_bwd_bytes": flow.total_bwd_bytes,
            "packet_length_mean": flow.packet_length_mean,
            "packet_length_std": flow.packet_length_std,
            "flow_bytes_s": flow.flow_bytes_s,
            "flow_packets_s": flow.flow_packets_s,
            "syn_flag_count": flow.syn_flag_count,
            "fin_flag_count": flow.fin_flag_count,
            "rst_flag_count": flow.rst_flag_count,
            "psh_flag_count": flow.psh_flag_count,
            "ack_flag_count": flow.ack_flag_count,
            "down_up_ratio": flow.down_up_ratio,
            "payload_entropy": flow.payload_entropy
        }
    }
    return service.process_flow(flow_dict)

@router.post("/simulate")
def simulate_traffic(req: SimulationBatchRequest):
    service = IDSService.get_instance()
    results = []
    
    types = [req.traffic_type] if req.traffic_type != "mixed" else ["benign", "dos", "portscan", "bruteforce", "botnet", "web"]
    
    for _ in range(req.count):
        t_type = types[0] if len(types) == 1 else (
            "benign" if __import__("random").random() < 0.60 else __import__("random").choice(types[1:])
        )
        sample = generate_flow_sample(t_type)
        res = service.process_flow(sample)
        results.append(res)

    return {
        "success": True,
        "count": len(results),
        "requested_type": req.traffic_type,
        "sample_preview": results[:5]
    }

@router.get("/recent")
def get_recent(limit: int = 50, threat_only: bool = False):
    return get_recent_flows(limit=limit, threat_only=threat_only)

@router.get("/flow/{flow_id}")
def get_single_flow(flow_id: str):
    flow = get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow

@router.post("/upload_csv")
async def upload_traffic_csv(file: UploadFile = File(...)):
    service = IDSService.get_instance()
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")

    content = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {e}")

    # Process first 100 rows
    processed = 0
    for _, row in df.head(100).iterrows():
        sample = generate_flow_sample("benign")  # fallback baseline
        # Map existing columns if present
        for col in sample["features"].keys():
            if col in df.columns:
                try:
                    sample["features"][col] = float(row[col])
                except (ValueError, TypeError):
                    pass
        if "src_ip" in df.columns:
            sample["src_ip"] = str(row["src_ip"])
        if "dst_port" in df.columns:
            try:
                sample["dst_port"] = int(row["dst_port"])
            except (ValueError, TypeError):
                pass

        service.process_flow(sample)
        processed += 1

    return {"success": True, "processed_rows": processed}
