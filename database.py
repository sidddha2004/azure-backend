import os
import time
from typing import Dict, List, Optional

import pandas as pd
import cyborgdb
from cyborgdb import Client
from sentence_transformers import SentenceTransformer, CrossEncoder

from dotenv import load_dotenv
from data_enrichment import TransactionEnricher

# ------------------------------------------------------------------
# LOAD ENVIRONMENT VARIABLES (CRITICAL FIX)
# ------------------------------------------------------------------
load_dotenv()   # <-- THIS WAS MISSING

# ------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------
CYBORG_URL = os.getenv("CYDB_URL", "http://127.0.0.1:8001")
API_KEY = os.getenv("CYDB_API_KEY")

if not API_KEY:
    raise RuntimeError("CYDB_API_KEY not set")

DEV_KEY = b"secure_dev_key_32_bytes_long_!!!"


class CyborgDB:
    """
    Dual-Index Federated Transaction Security System
    
    Architecture:
    - secure_history: Stores legitimate transaction patterns (The Detective)
    - known_threats: Stores fraud patterns from all banks (The Bouncer)
    """
    
    def __init__(self):
        print("🔌 Connecting to CyborgDB (Dual-Index Mode)...")
        
        # 1. BI-ENCODER (Fast Retrieval)
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # 2. CROSS-ENCODER (High-Precision Re-Ranking)
        print("🧠 Loading Cross-Encoder NLP Model...")
        self.cross_encoder = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
        
        # 3. Data Enrichment Engine
        print("🎨 Initializing Transaction Enricher...")
        self.enricher = TransactionEnricher()
        
        self.client = Client(base_url=CYBORG_URL, api_key=API_KEY)
        self.key = DEV_KEY

        # Create dual indexes
        self.history_index_name = "secure_history"
        self.threats_index_name = "known_threats"
        
        try:
            self.history_index = self.client.create_index(
                index_name=self.history_index_name, 
                index_key=self.key
            )
            print("✅ Created secure_history index")
        except Exception:
            self.history_index = self.client.load_index(
                index_name=self.history_index_name, 
                index_key=self.key
            )
            print("♻️  Loaded existing secure_history index")
            
        try:
            self.threats_index = self.client.create_index(
                index_name=self.threats_index_name, 
                index_key=self.key
            )
            print("✅ Created known_threats index")
        except Exception:
            self.threats_index = self.client.load_index(
                index_name=self.threats_index_name, 
                index_key=self.key
            )
            print("♻️  Loaded existing known_threats index")
        
        # Track what each bank has learned
        self.bank_knowledge = {
            'Bank A': {'normal_patterns': set(), 'threats': set()},
            'Bank B': {'normal_patterns': set(), 'threats': set()},
            'Bank C': {'normal_patterns': set(), 'threats': set()}
        }

    def create_vector(self, text_description: str):
        """Generate embedding vector from text description"""
        return self.model.encode(text_description).tolist()

    def calculate_risk(self, history_distance: float, threat_distance: float, 
                       amount: float, description: str, bank: str) -> str:
        """
        Dual-index risk assessment
        
        Args:
            history_distance: Distance to closest legitimate pattern
            threat_distance: Distance to closest known threat
            amount: Transaction amount
            description: Transaction description
            bank: Bank identifier
            
        Returns:
            Risk level string with reasoning
        """
        desc_lower = description.lower()
        
        # BOUNCER CHECK (Priority 1): Block known threats - LOWERED threshold
        if threat_distance < 0.6:
            return f"🚫 BLOCKED (Known Threat Match - Score: {threat_distance:.3f})"
        
        # CARD TESTING DETECTION - Enhanced
        if amount < 5.0 and any(w in desc_lower for w in ["verify", "verification", "auth", "check", "code", "hold", "test", "testing", "card"]):
            return "🚫 BLOCKED (Card Testing Pattern Detected)"
        
        # COLD START PROTECTION: Check if pattern is known
        if history_distance < 0.35:
            return f"✅ LOW RISK (Verified Pattern - Score: {history_distance:.3f})"
        elif history_distance < 0.75:
            return f"⚠️  MEDIUM RISK (Unusual Pattern - Score: {history_distance:.3f})"
        else:
            # High anomaly but not a known threat
            return f"🔴 HIGH RISK (Anomaly - Score: {history_distance:.3f})"


    def load_bank_data(self, bank_name: str, data: pd.DataFrame):
        """
        Load bank's portion of enriched dataset into dual indexes
        
        Args:
            bank_name: Name of the bank
            data: DataFrame with enriched_description, amount, isFraud, etc.
        """
        print(f"\n🏦 Loading data for {bank_name}...")
        
        legitimate = data[data['isFraud'] == 0]
        fraudulent = data[data['isFraud'] == 1]
        
        # Load legitimate patterns into secure_history (The Detective)
        history_records = []
        for idx, row in legitimate.iterrows():
            record = {
                "id": f"{bank_name}_{idx}_history",
                "vector": self.create_vector(row['enriched_description']),
                "metadata": {
                    "description": row['enriched_description'],
                    "amount": float(row['amount']),
                    "bank": bank_name,
                    "user_id": "system",
                    "timestamp": time.time(),
                    "pattern_type": row['type'],
                    "is_fraud": 0
                }
            }
            history_records.append(record)
            
            # Track learning
            self.bank_knowledge[bank_name]['normal_patterns'].add(row['type'])
        
        if history_records:
            self.history_index.upsert(history_records)
            print(f"   ✅ Loaded {len(history_records)} legitimate patterns to secure_history")
        
        # Load fraud patterns into known_threats (The Bouncer)
        threat_records = []
        for idx, row in fraudulent.iterrows():
            record = {
                "id": f"{bank_name}_{idx}_threat",
                "vector": self.create_vector(row['enriched_description']),
                "metadata": {
                    "description": row['enriched_description'],
                    "amount": float(row['amount']),
                    "bank": bank_name,
                    "user_id": "system",
                    "timestamp": time.time(),
                    "pattern_type": row['type'],
                    "is_fraud": 1,
                    "threat_level": "HIGH"
                }
            }
            threat_records.append(record)
            
            # Track threats
            self.bank_knowledge[bank_name]['threats'].add(row['enriched_description'][:50])
        
        if threat_records:
            self.threats_index.upsert(threat_records)
            print(f"   🚨 Loaded {len(threat_records)} fraud patterns to known_threats")
        
        # Print what this bank learned
        print(f"\n   📚 {bank_name} Knowledge Base:")
        print(f"      Normal Patterns: {', '.join(self.bank_knowledge[bank_name]['normal_patterns'])}")
        print(f"      Known Threats: {len(self.bank_knowledge[bank_name]['threats'])} unique patterns")

    def secure_storage(self, txn_id: str, description: str, amount: float, 
                       bank: str, user_id: str, is_fraud: int = 0):
        """
        Store new transaction in appropriate index
        
        Args:
            txn_id: Unique transaction ID
            description: Transaction description (already enriched if from user)
            amount: Transaction amount
            bank: Bank identifier
            user_id: User identifier
            is_fraud: 0 for normal, 1 for fraud
            
        Returns:
            Success boolean
        """
        try:
            vector = self.create_vector(description)
            
            metadata = {
                "description": description,
                "amount": amount,
                "bank": bank,
                "user_id": user_id,
                "timestamp": time.time(),
                "is_fraud": is_fraud
            }
            
            record = {
                "id": txn_id,
                "vector": vector,
                "metadata": metadata
            }
            
            # Route to appropriate index
            if is_fraud == 1:
                self.threats_index.upsert([record])
                print(f"🚨 Stored threat: '{description}' ({bank})")
            else:
                self.history_index.upsert([record])
                print(f"✅ Stored to history: '{description}' ({bank})")
            
            return True
        except Exception as e:
            print(f"❌ Storage Error: {e}")
            return False

    def delete_transaction(self, txn_id: str):
        """Delete transaction from both indexes"""
        try:
            # Try both indexes
            try:
                self.history_index.delete([txn_id])
            except:
                pass
            try:
                self.threats_index.delete([txn_id])
            except:
                pass
            return True
        except Exception as e:
            return False

    def secure_search(self, query_text: str, bank_filter: str = "All", 
                      min_amount: float = 0, user_id_filter: Optional[str] = None):
        """
        Dual-index search with risk assessment and PROPER USER FILTERING
        
        FIXED: Users now only see their own bank's transactions
        """
        try:
            # Determine user's bank based on user_id
            user_bank_map = {
                'Alice': 'Bank A',
                'Bob': 'Bank B',
                'Charlie': 'Bank C'
            }
            
            # For non-admin users, override bank_filter with their bank
            if user_id_filter and user_id_filter != "admin":
                if user_id_filter in user_bank_map:
                    bank_filter = user_bank_map[user_id_filter]
                    print(f"🔒 Filtering for {user_id_filter}'s bank: {bank_filter}")
            
            # Better default: show recent legitimate transactions, not threats
            if not query_text.strip():
                target_query = "payment transfer purchase spent money transaction" 
            else:
                target_query = query_text

            query_vector = self.create_vector(target_query)
            
            # Search both indexes with INCREASED top_k for better real-time updates
            history_results = self.history_index.query(query_vectors=query_vector, top_k=100)
            threat_results = self.threats_index.query(query_vectors=query_vector, top_k=100)
            
            matches = []
            
            # Process history results (legitimate patterns)
            for res in history_results:
                meta = res.get('metadata', {})
                distance = res.get('distance', 0.0)
                txn_id = res.get('id')
                
                # CRITICAL FIX: Apply user filter FIRST
                if user_id_filter and user_id_filter != "admin":
                    # For non-admin users, ONLY show their bank's transactions
                    if meta.get("bank") != bank_filter:
                        continue
                
                # Then apply other filters
                if bank_filter != "All" and meta.get("bank") != bank_filter: 
                    continue
                if float(meta.get("amount", 0)) < min_amount: 
                    continue

                # Check if this transaction has a similar threat
                min_threat_distance = 999.0
                for threat in threat_results:
                    t_dist = threat.get('distance', 999)
                    if t_dist < min_threat_distance:
                        min_threat_distance = t_dist
                
                matches.append({
                    "id": txn_id, 
                    "score": distance,
                    "risk_level": self.calculate_risk(
                        distance, 
                        min_threat_distance,
                        meta.get('amount', 0), 
                        meta.get('description', ''),
                        meta.get('bank', '')
                    ),
                    "metadata": meta,
                    "index_source": "secure_history"
                })
            
            # ADMIN ONLY: Show threats from known_threats index
            if user_id_filter == "admin" or user_id_filter is None:
                for res in threat_results:
                    meta = res.get('metadata', {})
                    distance = res.get('distance', 0.0)
                    txn_id = res.get('id')
                    
                    # Only show reasonably close matches to query
                    if distance > 1.5:
                        continue
                    
                    if bank_filter != "All" and meta.get("bank") != bank_filter: 
                        continue
                    if float(meta.get("amount", 0)) < min_amount: 
                        continue
                    
                    # If it's in known_threats, it's ALWAYS a threat
                    matches.append({
                        "id": txn_id, 
                        "score": distance,
                        "risk_level": f"🚫 BLOCKED (Known Threat Pattern)",
                        "metadata": meta,
                        "index_source": "known_threats"
                    })
            
            # Sort by timestamp (most recent first) for real-time updates
            matches.sort(key=lambda x: x['metadata'].get('timestamp', 0), reverse=True)
            
            return matches[:30]  # Increased to show more recent transactions

        except Exception as e:
            print(f"❌ Search Error: {e}")
            return []

    def broadcast_threat(self, source_bank: str, threat_description: str) -> Dict[str, int]:
        """
        Broadcast threat pattern to all banks in the network
        
        This simulates federated learning where one bank shares a discovered
        threat pattern with others. Searches BOTH secure_history (to flag similar
        legitimate patterns) AND known_threats (to share threat intelligence)
        
        Args:
            source_bank: Bank that discovered the threat
            threat_description: Description of the threat pattern
            
        Returns:
            Dictionary with impact statistics per bank
        """
        try:
            print(f"\n📡 Broadcasting Threat from {source_bank}")
            print(f"   Pattern: '{threat_description}'")
            
            # Generate semantic variations of the threat for better matching
            desc_lower = threat_description.lower()
            search_variants = [threat_description]
            
            # Add variations based on common fraud terms
            if 'offshore' in desc_lower or 'shell' in desc_lower:
                search_variants.extend([
                    "foreign account transfer",
                    "international wire transfer",
                    "cross border payment",
                    "suspicious foreign transaction"
                ])
            
            if 'money laundering' in desc_lower or 'layering' in desc_lower:
                search_variants.extend([
                    "suspicious transfer pattern",
                    "complex transaction chain",
                    "multiple transfer sequence"
                ])
            
            if 'stolen' in desc_lower or 'unauthorized' in desc_lower:
                search_variants.extend([
                    "fraudulent transaction",
                    "suspicious card usage",
                    "unauthorized access"
                ])
            
            if 'card testing' in desc_lower or 'verification' in desc_lower:
                search_variants.extend([
                    "small verification charge",
                    "card validation attempt",
                    "authorization test"
                ])
            
            # STAGE 1: Search both indexes for comprehensive coverage
            all_candidates = []
            all_metadata = []
            all_banks = []
            
            print(f"   🔍 Searching with {len(search_variants)} pattern variations...")
            
            for variant in search_variants:
                variant_vector = self.create_vector(variant)
                
                # Search legitimate history (might contain similar but not flagged)
                history_results = self.history_index.query(query_vectors=variant_vector, top_k=50)
                
                for res in history_results:
                    meta = res.get('metadata', {})
                    desc = meta.get('description', '')
                    bank = meta.get('bank', '')
                    
                    # Only check other banks
                    if bank == source_bank: 
                        continue
                    
                    all_candidates.append([threat_description, desc])
                    all_metadata.append(meta)
                    all_banks.append(bank)
                
                # Also search existing threats (for cross-bank threat sharing)
                threat_results = self.threats_index.query(query_vectors=variant_vector, top_k=30)
                
                for res in threat_results:
                    meta = res.get('metadata', {})
                    desc = meta.get('description', '')
                    bank = meta.get('bank', '')
                    
                    if bank == source_bank:
                        continue
                    
                    all_candidates.append([threat_description, desc])
                    all_metadata.append(meta)
                    all_banks.append(bank)
            
            if not all_candidates:
                print("   ℹ️  No matches found in other banks")
                return {"Bank A": 0, "Bank B": 0, "Bank C": 0}

            # Remove duplicates by description
            unique_candidates = []
            unique_metadata = []
            unique_banks = []
            seen_descriptions = set()
            
            for pair, meta, bank in zip(all_candidates, all_metadata, all_banks):
                desc = pair[1]
                if desc not in seen_descriptions:
                    seen_descriptions.add(desc)
                    unique_candidates.append(pair)
                    unique_metadata.append(meta)
                    unique_banks.append(bank)
            
            # STAGE 2: AI Re-Ranking with Cross-Encoder
            print(f"   🧠 AI analyzing {len(unique_candidates)} unique transactions...")
            scores = self.cross_encoder.predict(unique_candidates)

            network_stats = {"Bank A": 0, "Bank B": 0, "Bank C": 0}
            moved_to_threats = []
            
            for i, score in enumerate(scores):
                bank = unique_banks[i]
                target_desc = unique_candidates[i][1]
                meta = unique_metadata[i]
                
                # Progressive threshold: lower for better semantic matching
                if score > 0.2:
                    print(f"      ✅ MATCH: '{target_desc}' (Score: {score:.2f}) in {bank}")
                    if bank in network_stats:
                        network_stats[bank] += 1
                    
                    # Move to threats index (Federated Learning Update)
                    threat_vector = self.create_vector(target_desc)
                    threat_record = {
                        "id": f"broadcast_{source_bank}_{bank}_{i}_{int(time.time() * 1000)}",
                        "vector": threat_vector,
                        "metadata": {
                            **meta,
                            "is_fraud": 1,
                            "threat_level": "HIGH",
                            "learned_from": source_bank,
                            "broadcast_timestamp": time.time(),
                            "original_threat": threat_description,
                            "match_score": float(score)
                        }
                    }
                    moved_to_threats.append(threat_record)
                elif score > 0.0:
                    # Log near-misses for debugging
                    print(f"      ⚠️  Near miss: '{target_desc}' (Score: {score:.2f})")
            
            # Batch update known_threats index
            if moved_to_threats:
                self.threats_index.upsert(moved_to_threats)
                print(f"\n   🛡️  Updated {len(moved_to_threats)} patterns to global threat database")
            else:
                print(f"\n   ℹ️  No strong matches found (threshold: 0.2)")
                print(f"      Highest score: {max(scores) if len(scores) > 0 else 'N/A'}")
            
            # Remove source bank from stats
            if source_bank in network_stats:
                del network_stats[source_bank]
                
            return network_stats

        except Exception as e:
            print(f"❌ Broadcast Error: {e}")
            import traceback
            traceback.print_exc()
            return {"Bank A": 0, "Bank B": 0, "Bank C": 0}

    def trigger_training(self):
        """Simulate index optimization"""
        time.sleep(1.5)
        print("⚡ Indexes optimized")
        return True
    
    def get_network_stats(self) -> Dict:
        """Get statistics about the federated network"""
        stats = {}
        for bank, knowledge in self.bank_knowledge.items():
            stats[bank] = {
                "normal_patterns": len(knowledge['normal_patterns']),
                "known_threats": len(knowledge['threats'])
            }
        return stats