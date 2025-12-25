import random
import time
from database import CyborgDB

# --- CONFIGURATION ---
TOTAL_TRANSACTIONS = 600  # Total history to generate
FRAUD_RATIO = 0.05        # 5% of data is fraud

# --- ENRICHMENT LOGIC (The "Translator") ---
def enrich_transaction(txn_type, amount, is_fraud):
    """
    Converts raw numbers into Semantic Text based on the logic we designed.
    """
    # 1. FRAUD PATTERNS (The Bouncer's List)
    if is_fraud:
        fraud_scenarios = [
            "Offshore Shell Corp Transfer", 
            "Stolen Card ATM Withdrawal", 
            "Phishing Link Payment Verification", 
            "Darkweb Crypto Purchase", 
            "Structuring Layering Transfer"
        ]
        return random.choice(fraud_scenarios)

    # 2. NORMAL PATTERNS (The Detective's History)
    if txn_type == "PAYMENT":
        if amount < 20: 
            return random.choice(["Uber Ride Verification", "Starbucks Coffee", "Spotify Subscription", "Netflix Monthly"])
        elif amount < 100:
            return random.choice(["Shell Gas Station", "Target Store Purchase", "Walmart Grocery", "Amazon Prime Order"])
        else:
            return "Best Buy Electronics"
            
    elif txn_type == "TRANSFER":
        if amount < 1000:
            return random.choice(["Monthly Rent Payment", "Family Support Transfer", "Utility Bill Payment"])
        else:
            return "Tuition Fee Wire"
            
    elif txn_type == "CASH_OUT":
        return "ATM Withdrawal Personal"
    
    return "General Merchant Purchase"

# --- THE LOADER ---
def run_federated_seeding():
    print("🚀 Starting Federated Data Seeding...")
    db = CyborgDB()
    
    # Reset Databases for clean slate
    print("🧹 Cleaning old indexes...")
    # We use internal methods or just overwrite by upserting
    
    banks = ["Bank A", "Bank B", "Bank C"]
    data_buffer = []

    print(f"🏭 Synthesizing {TOTAL_TRANSACTIONS} Enriched Transactions...")
    
    for _ in range(TOTAL_TRANSACTIONS):
        # 1. Generate Raw Data (Simulating PaySim)
        is_fraud = random.random() < FRAUD_RATIO
        txn_type = random.choice(["PAYMENT", "TRANSFER", "CASH_OUT"])
        amount = round(random.uniform(5.0, 2000.0), 2)
        
        # 2. Apply Enrichment
        description = enrich_transaction(txn_type, amount, is_fraud)
        
        # 3. Assign to Bank (The Split)
        bank = random.choice(banks)
        
        data_buffer.append({
            "bank": bank,
            "amount": amount,
            "description": description,
            "is_fraud": is_fraud
        })

    # 4. Ingest into CyborgDB
    print("💾 Seeding Dual-Layer Indexes (Detective & Bouncer)...")
    
    for i, item in enumerate(data_buffer):
        txn_id = f"seed-{i}"
        
        # ROUTING LOGIC
        if item["is_fraud"]:
            # Fraud goes to 'known_threats' (The Bouncer)
            db.add_to_bouncer(item["description"], item["bank"])
        else:
            # Normal goes to 'secure_history' (The Detective)
            db.add_to_history(txn_id, item["description"], item["amount"], item["bank"], "system_loader")
            
        if i % 50 == 0:
            print(f"   ... Processed {i}/{TOTAL_TRANSACTIONS} rows ...")

    print("\n✅ FEDERATED SEEDING COMPLETE!")
    print(f"   - Bank A, B, C now have local 'Normal History'.")
    print(f"   - Known Frauds are stored in local 'Blocklists'.")

if __name__ == "__main__":
    run_federated_seeding()