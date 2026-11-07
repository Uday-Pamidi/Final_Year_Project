import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print("Starting Adaptive IDS (DICI Framework - Lin et al. IEEE TMLCN 2025)")
    print("Hybrid XGBoost + Isolation Forest + CTI Transfer + Drift + SHAP")
    print("Server running at: http://127.0.0.1:8000")
    print("Interactive API Docs: http://127.0.0.1:8000/docs")
    print("=" * 70)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
