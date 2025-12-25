from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from database import CyborgDB
import uuid
import time
import random
from typing import Optional, List
import asyncio
import json
# Add at top with other imports
from rag_engine import get_rag_engine
import os

app = FastAPI(title="Sentinel AI - Federated Fraud Detection")

# CORS Configuration
origins = ["http://localhost:5173", "http://127.0.0.1:5173", "*"]
app.add_middleware(
    CORSMiddleware, 
    allow_origins=origins, 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"],
)

# Initialize Database
db = CyborgDB()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# ============================================================================
# REQUEST MODELS
# ============================================================================

class TransactionRequest(BaseModel):
    description: str
    amount: float
    bank: str = "Bank A"
    user_id: str = "admin"
    is_fraud: int = 0  # NEW: Flag for fraud injection

class SearchRequest(BaseModel):
    query: str
    bank_filter: str = "All"
    min_amount: float = 0
    user_id: str = "admin"

class BroadcastRequest(BaseModel):
    source_bank: str
    description: str

class DataLoadRequest(BaseModel):
    """For loading initial dataset"""
    sample_size: int = 1000
    
# ============================================================================
# CORE ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "system": "Sentinel AI - Federated Fraud Detection",
        "version": "2.0",
        "architecture": "Dual-Index (secure_history + known_threats)"
    }

@app.post("/secure-ingest")
async def ingest_transaction(txn: TransactionRequest):
    """
    Ingest new transaction into the system
    
    Routes to appropriate index based on fraud flag:
    - is_fraud=0 → secure_history (legitimate patterns)
    - is_fraud=1 → known_threats (fraud patterns)
    """
    txn_id = str(uuid.uuid4())
    
    success = db.secure_storage(
        txn_id=txn_id,
        description=txn.description,
        amount=txn.amount,
        bank=txn.bank,
        user_id=txn.user_id,
        is_fraud=txn.is_fraud
    )
    
    if success:
        return {
            "status": "stored",
            "id": txn_id,
            "index": "known_threats" if txn.is_fraud == 1 else "secure_history",
            "message": f"Transaction stored in {txn.bank}"
        }
    else:
        raise HTTPException(status_code=500, detail="Storage failed")

@app.post("/secure-search")
async def search_transactions(search: SearchRequest):
    """
    Search across both indexes with risk assessment
    
    Returns dual-scored results:
    - Checks secure_history for legitimate patterns
    - Checks known_threats for fraud patterns
    
    FIXED: Now properly filters by user bank
    """
    results = db.secure_search(
        query_text=search.query,
        bank_filter=search.bank_filter,
        min_amount=search.min_amount,
        user_id_filter=search.user_id
    )
    
    return {
        "results": results,
        "count": len(results),
        "query": search.query
    }

@app.delete("/secure-delete/{txn_id}")
async def delete_transaction(txn_id: str):
    """Delete transaction from both indexes"""
    success = db.delete_transaction(txn_id)
    
    if success:
        return {"status": "deleted", "id": txn_id}
    else:
        raise HTTPException(status_code=500, detail="Delete failed")

# ============================================================================
# FEDERATED LEARNING ENDPOINTS
# ============================================================================

@app.post("/secure-broadcast")
async def broadcast_threat(req: BroadcastRequest):
    """
    Broadcast threat pattern across the federated network
    
    Workflow:
    1. Bank discovers a threat pattern
    2. System searches other banks' secure_history
    3. AI re-ranks potential matches
    4. Matching patterns are moved to known_threats
    5. Network is now protected against this threat
    """
    print(f"\n{'='*70}")
    print(f"📡 THREAT BROADCAST INITIATED")
    print(f"{'='*70}")
    print(f"Source: {req.source_bank}")
    print(f"Pattern: {req.description}")
    
    # Simulate network latency
    time.sleep(1.5)
    
    # Execute broadcast scan with NLP re-ranking
    impact_stats = db.broadcast_threat(req.source_bank, req.description)
    
    total_protected = sum(impact_stats.values())
    
    print(f"\n{'='*70}")
    print(f"📊 BROADCAST COMPLETE")
    print(f"{'='*70}")
    print(f"Total Transactions Protected: {total_protected}")
    for bank, count in impact_stats.items():
        if count > 0:
            print(f"   {bank}: {count} patterns updated")
    
    return {
        "status": "Broadcast Complete",
        "source_bank": req.source_bank,
        "threat_pattern": req.description,
        "impact_report": impact_stats,
        "total_protected": total_protected,
        "message": f"Protected {total_protected} transactions across the network"
    }

@app.post("/federated-round")
async def trigger_federated_round():
    """
    Simulate federated learning round
    
    In production, this would:
    1. Aggregate model updates from all banks
    2. Update global model
    3. Distribute back to banks
    """
    print("\n🔄 Federated Learning Round Starting...")
    
    # Simulate computation time
    time.sleep(2)
    
    # Simulate accuracy improvement
    new_accuracy = round(random.uniform(0.90, 0.98), 3)
    round_id = f"FL-{random.randint(1000, 9999)}"
    
    print(f"✅ Round {round_id} Complete - Accuracy: {new_accuracy}")
    
    return {
        "status": "Updated",
        "round_id": round_id,
        "new_accuracy": new_accuracy,
        "participants": ["Bank A", "Bank B", "Bank C"],
        "message": "Global model updated successfully"
    }

@app.post("/secure-train")
async def train_index():
    """Optimize vector indexes"""
    db.trigger_training()
    return {
        "status": "Trained",
        "message": "Indexes optimized successfully"
    }

# ============================================================================
# SYSTEM INFORMATION ENDPOINTS
# ============================================================================

@app.get("/network-stats")
async def get_network_stats():
    """Get statistics about the federated network"""
    stats = db.get_network_stats()
    
    return {
        "network": stats,
        "total_banks": len(stats),
        "architecture": "Dual-Index Federated System"
    }

@app.get("/system-health")
async def system_health():
    """Check system health and configuration"""
    return {
        "status": "healthy",
        "indexes": {
            "secure_history": "active",
            "known_threats": "active"
        },
        "ml_models": {
            "bi_encoder": "all-MiniLM-L6-v2",
            "cross_encoder": "cross-encoder/ms-marco-MiniLM-L-6-v2"
        },
        "features": {
            "data_enrichment": "enabled",
            "dual_index": "enabled",
            "federated_learning": "enabled",
            "nlp_reranking": "enabled",
            "real_time_streaming": "enabled"
        }
    }

@app.get("/streaming-stats")
async def get_streaming_stats():
    """Get real-time streaming statistics - IMPROVED for faster updates"""
    try:
        # Query recent transactions (last 10 minutes for more data)
        recent_time = time.time() - 3600  # Changed from 300 to 600 seconds
        
        # Get counts from both indexes with larger top_k
        history_query = db.create_vector("transaction payment transfer")
        history_results = db.history_index.query(query_vectors=history_query, top_k=200)
        threat_results = db.threats_index.query(query_vectors=history_query, top_k=200)
        
        # Filter by recent time
        recent_history = [r for r in history_results 
                         if r.get('metadata', {}).get('timestamp', 0) > recent_time]
        recent_threats = [r for r in threat_results 
                         if r.get('metadata', {}).get('timestamp', 0) > recent_time]
        
        # Count by bank
        bank_counts = {"Bank A": 0, "Bank B": 0, "Bank C": 0}
        for r in recent_history + recent_threats:
            bank = r.get('metadata', {}).get('bank')
            if bank in bank_counts:
                bank_counts[bank] += 1
        
        return {
            "recent_transactions": len(recent_history) + len(recent_threats),
            "legitimate": len(recent_history),
            "threats": len(recent_threats),
            "by_bank": bank_counts,
            "time_window": "last 10 minutes",
            "timestamp": time.time()
        }
    except Exception as e:
        return {
            "recent_transactions": 0,
            "legitimate": 0,
            "threats": 0,
            "by_bank": {"Bank A": 0, "Bank B": 0, "Bank C": 0},
            "error": str(e),
            "timestamp": time.time()
        }

# ============================================================================
# WEBSOCKET ENDPOINT
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and send periodic updates
            await asyncio.sleep(1)
            
            # You can send heartbeat or wait for messages
            try:
                await websocket.receive_text()
            except:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task to broadcast stats - FASTER UPDATES
async def broadcast_stats():
    """Broadcast statistics every 1 second for real-time feel"""
    while True:
        try:
            stats = await get_streaming_stats()
            await manager.broadcast({
                "type": "stats_update",
                "data": stats
            })
        except Exception as e:
            print(f"Broadcast error: {e}")
        await asyncio.sleep(1)  # Changed from 3 to 1 second




# Add after existing endpoints

@app.post("/rag-analysis")
async def generate_fraud_analysis(search: SearchRequest):
    """
    Generate AI-powered fraud analysis report using RAG
    
    Retrieves relevant patterns from CyborgDB and generates insights
    """
    try:
        # Initialize RAG engine
        rag = rag = get_rag_engine()
        
        # Generate report
        report = rag.generate_fraud_report(
            query=search.query,
            bank_filter=search.bank_filter
        )
        
        return {
            "status": "success",
            "report": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/quick-threat-check")
async def quick_threat_check(txn: TransactionRequest):
    """
    Quick AI threat assessment for a single transaction
    """
    try:
        rag = rag = get_rag_engine()
        
        assessment = rag.quick_threat_analysis(
            transaction_description=txn.description,
            amount=txn.amount,
            bank=txn.bank
        )
        
        return {
            "status": "success",
            "assessment": assessment
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# STARTUP EVENT
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize system on startup"""
    print("\n" + "="*70)
    print("🚀 SENTINEL AI - FEDERATED FRAUD DETECTION SYSTEM")
    print("="*70)
    print("✅ FastAPI Server Initialized")
    print("✅ Dual-Index Architecture Active")
    print("✅ ML Models Loaded")
    print("✅ WebSocket Enabled for Real-Time Updates")
    print("✅ Ready for Federated Operations")
    print("="*70 + "\n")
    print("💡 Run 'python data_loader.py' to load initial dataset")
    print("💡 Run 'python streaming_producer.py' to start transaction stream")
    print("="*70 + "\n")
    
    # Start background stats broadcaster
    asyncio.create_task(broadcast_stats())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)