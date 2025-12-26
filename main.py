from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import uuid
import time
import random
import asyncio
import os

from database import CyborgDB
from rag_engine import get_rag_engine

# =============================================================================
# APP INITIALIZATION
# =============================================================================

app = FastAPI(title="Sentinel AI - Federated Fraud Detection")

# -----------------------------------------------------------------------------
# CORS (Azure-safe)
# -----------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://<cydb-frontend>.azurestaticapps.net","*"
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# DATABASE
# -----------------------------------------------------------------------------

db = CyborgDB()

# -----------------------------------------------------------------------------
# RAG ENGINE (LAZY SINGLETON)
# -----------------------------------------------------------------------------

_rag_engine = None

def get_rag():
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = get_rag_engine()
    return _rag_engine

# -----------------------------------------------------------------------------
# WEBSOCKET MANAGER
# -----------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

# =============================================================================
# REQUEST MODELS
# =============================================================================

class TransactionRequest(BaseModel):
    description: str
    amount: float
    bank: str = "Bank A"
    user_id: str = "admin"
    is_fraud: int = 0

class SearchRequest(BaseModel):
    query: str
    bank_filter: str = "All"
    min_amount: float = 0
    user_id: str = "admin"

class BroadcastRequest(BaseModel):
    source_bank: str
    description: str

# =============================================================================
# CORE ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    return {
        "status": "online",
        "system": "Sentinel AI - Federated Fraud Detection",
        "version": "2.0"
    }

@app.post("/secure-ingest")
async def ingest_transaction(txn: TransactionRequest):
    txn_id = str(uuid.uuid4())

    success = db.secure_storage(
        txn_id=txn_id,
        description=txn.description,
        amount=txn.amount,
        bank=txn.bank,
        user_id=txn.user_id,
        is_fraud=txn.is_fraud
    )

    if not success:
        raise HTTPException(status_code=500, detail="Storage failed")

    return {
        "status": "stored",
        "id": txn_id,
        "index": "known_threats" if txn.is_fraud else "secure_history"
    }

@app.post("/secure-search")
async def search_transactions(search: SearchRequest):
    results = db.secure_search(
        query_text=search.query,
        bank_filter=search.bank_filter,
        min_amount=search.min_amount,
        user_id_filter=search.user_id
    )

    return {
        "results": results,
        "count": len(results)
    }

@app.delete("/secure-delete/{txn_id}")
async def delete_transaction(txn_id: str):
    if not db.delete_transaction(txn_id):
        raise HTTPException(status_code=500, detail="Delete failed")
    return {"status": "deleted", "id": txn_id}

# =============================================================================
# FEDERATED LEARNING
# =============================================================================

@app.post("/secure-broadcast")
async def broadcast_threat(req: BroadcastRequest):
    await asyncio.sleep(1.5)  # NON-BLOCKING

    impact_stats = db.broadcast_threat(req.source_bank, req.description)
    total = sum(impact_stats.values())

    return {
        "status": "complete",
        "impact_report": impact_stats,
        "total_protected": total
    }

@app.post("/federated-round")
async def trigger_federated_round():
    await asyncio.sleep(2)  # NON-BLOCKING

    return {
        "round_id": f"FL-{random.randint(1000,9999)}",
        "accuracy": round(random.uniform(0.90, 0.98), 3),
        "participants": ["Bank A", "Bank B", "Bank C"]
    }

@app.post("/secure-train")
async def train_index():
    db.trigger_training()
    return {"status": "trained"}

# =============================================================================
# SYSTEM ENDPOINTS
# =============================================================================

@app.get("/network-stats")
async def get_network_stats():
    stats = db.get_network_stats()
    return {"network": stats}

@app.get("/system-health")
async def system_health():
    return {
        "status": "healthy",
        "indexes": ["secure_history", "known_threats"],
        "ml": "lazy-loaded"
    }

# =============================================================================
# STREAMING STATS
# =============================================================================

@app.get("/streaming-stats")
async def get_streaming_stats():
    try:
        recent_time = time.time() - 3600

        query_vec = db.create_vector("transaction payment transfer")
        history = db.history_index.query(query_vectors=query_vec, top_k=200)
        threats = db.threats_index.query(query_vectors=query_vec, top_k=200)

        recent = [
            r for r in history + threats
            if r.get("metadata", {}).get("timestamp", 0) > recent_time
        ]

        return {
            "recent_transactions": len(recent),
            "timestamp": time.time()
        }
    except Exception as e:
        return {"error": str(e)}

# =============================================================================
# WEBSOCKET
# =============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            try:
                # Keep connection alive (Azure-friendly)
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                # Heartbeat every 30s so Azure doesn't kill it
                await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# =============================================================================
# BACKGROUND TASK
# =============================================================================

async def broadcast_stats():
    while True:
        try:
            stats = await get_streaming_stats()
            await manager.broadcast({"type": "stats", "data": stats})
        except Exception:
            pass
        await asyncio.sleep(1)

# =============================================================================
# RAG ENDPOINTS
# =============================================================================

@app.post("/rag-analysis")
async def generate_fraud_analysis(search: SearchRequest):
    rag = get_rag()
    report = rag.generate_fraud_report(
        query=search.query,
        bank_filter=search.bank_filter
    )
    return {"status": "success", "report": report}

@app.post("/quick-threat-check")
async def quick_threat_check(txn: TransactionRequest):
    rag = get_rag()
    assessment = rag.quick_threat_analysis(
        transaction_description=txn.description,
        amount=txn.amount,
        bank=txn.bank
    )
    return {"status": "success", "assessment": assessment}

# =============================================================================
# STARTUP
# =============================================================================

_broadcast_task = None

@app.on_event("startup")
async def startup_event():
    global _broadcast_task

    print("\n🚀 Sentinel AI backend starting (Azure)")
    print("⏳ ML models will load lazily on first request")

    if _broadcast_task is None:
        _broadcast_task = asyncio.create_task(broadcast_stats())
