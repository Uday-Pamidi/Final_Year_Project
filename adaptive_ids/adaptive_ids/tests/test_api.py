import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_pages_render(client):
    # Test all Jinja2 web page endpoints including separate Home and Dashboard
    routes = ["/", "/dashboard", "/live", "/cti", "/drift", "/explain", "/docs-view", "/404"]
    for r in routes:
        res = client.get(r)
        assert res.status_code in [200, 404]
        assert "html" in res.headers.get("content-type", "")

def test_system_stats_api(client):
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_flows" in data
    assert "attacks_detected" in data

def test_cti_signatures_api(client):
    res = client.get("/api/cti/signatures")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) > 0

def test_traffic_simulation_and_explain(client):
    # Ingest 3 simulated flows
    sim_res = client.post("/api/traffic/simulate", json={"traffic_type": "dos", "count": 3})
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["count"] == 3

    # Check recent flows
    recent_res = client.get("/api/traffic/recent?limit=5")
    assert recent_res.status_code == 200
    flows = recent_res.json()
    assert len(flows) > 0

    # Test SHAP explanation for the first flow
    first_id = flows[0]["id"]
    explain_res = client.get(f"/api/explain/flow/{first_id}")
    assert explain_res.status_code == 200
    explain_data = explain_res.json()
    assert "feature_contributions" in explain_data
    assert "analyst_summary" in explain_data

def test_drift_status_api(client):
    res = client.get("/api/drift/status")
    assert res.status_code == 200
    data = res.json()
    assert "overall_status" in data
    assert "metrics" in data
