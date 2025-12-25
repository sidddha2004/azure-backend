"""
DATA LOADER SCRIPT
Loads PaySim dataset, enriches it, and distributes across banks for federated learning
"""

import pandas as pd
import os
from database import CyborgDB
from data_enrichment import TransactionEnricher

def load_and_prepare_data(dataset_path: str, sample_size: int = 1000):
    """
    Load PaySim dataset and prepare for federated learning
    
    Args:
        dataset_path: Path to PaySim CSV file
        sample_size: Number of transactions to load (for demo purposes)
        
    Returns:
        Enriched DataFrame
    """
    print("📂 Loading PaySim dataset...")
    
    # Check if file exists
    if not os.path.exists(dataset_path):
        print(f"⚠️  Dataset not found at {dataset_path}")
        print("   Creating synthetic sample data for demonstration...")
        
        # Create synthetic data matching PaySim format
        import numpy as np
        np.random.seed(42)
        
        types = ['PAYMENT', 'TRANSFER', 'CASH_OUT', 'DEBIT', 'CASH_IN']
        
        data = {
            'step': np.random.randint(1, 100, sample_size),
            'type': np.random.choice(types, sample_size),
            'amount': np.random.lognormal(3, 2, sample_size),  # Log-normal distribution
            'nameOrig': [f'C{i}' for i in range(sample_size)],
            'oldbalanceOrg': np.random.uniform(0, 100000, sample_size),
            'newbalanceOrig': np.random.uniform(0, 100000, sample_size),
            'nameDest': [f'M{i}' for i in range(sample_size)],
            'oldbalanceDest': np.random.uniform(0, 100000, sample_size),
            'newbalanceDest': np.random.uniform(0, 100000, sample_size),
            'isFraud': np.random.choice([0, 1], sample_size, p=[0.95, 0.05]),  # 5% fraud
            'isFlaggedFraud': np.random.choice([0, 1], sample_size, p=[0.99, 0.01])
        }
        
        df = pd.DataFrame(data)
        print(f"   ✅ Created {sample_size} synthetic transactions")
    else:
        # Load real dataset
        df = pd.read_csv(dataset_path)
        print(f"   ✅ Loaded {len(df)} transactions from dataset")
        
        # Sample if needed
        if sample_size and sample_size < len(df):
            df = df.sample(n=sample_size, random_state=42)
            print(f"   📊 Sampled {sample_size} transactions for demo")
    
    return df


def main():
    """Main execution flow"""
    print("=" * 70)
    print("🚀 FEDERATED FRAUD DETECTION SYSTEM - DATA INITIALIZATION")
    print("=" * 70)
    
    # Configuration
    DATASET_PATH = "data/transactions.csv"  # Path to your PaySim dataset
    SAMPLE_SIZE = 10000  # Total transactions to use
    STREAMING_RATIO = 0.70  # 70% for streaming simulation
    FL_RATIO = 0.30  # 30% for FL initial training
    
    # Step 1: Load raw data
    raw_data = load_and_prepare_data(DATASET_PATH, SAMPLE_SIZE)
    
    # Step 2: Enrich data with semantic descriptions
    enricher = TransactionEnricher()
    enriched_data = enricher.enrich_dataset(raw_data)
    
    print("\n" + "=" * 70)
    print("📊 SAMPLE ENRICHED DATA")
    print("=" * 70)
    print(enriched_data[['type', 'amount', 'isFraud', 'enriched_description']].head(10))
    
    # Step 3: Split data for streaming vs FL initial training
    print("\n" + "=" * 70)
    print("🔀 SPLITTING DATA FOR STREAMING + FL")
    print("=" * 70)
    
    streaming_size = int(len(enriched_data) * STREAMING_RATIO)
    
    # Shuffle data first for realistic distribution
    enriched_data = enriched_data.sample(frac=1, random_state=42).reset_index(drop=True)
    
    streaming_data = enriched_data[:streaming_size].copy()
    fl_initial_data = enriched_data[streaming_size:].copy()
    
    print(f"📤 Streaming Dataset: {len(streaming_data)} transactions ({STREAMING_RATIO*100:.0f}%)")
    print(f"   - Will be used for real-time simulation")
    print(f"   - Saved to: data/streaming_transactions.csv")
    print(f"\n🤖 FL Initial Training: {len(fl_initial_data)} transactions ({FL_RATIO*100:.0f}%)")
    print(f"   - Will be loaded into CyborgDB at startup")
    print(f"   - Provides initial threat intelligence")
    
    # Save streaming data for producer to use
    streaming_data.to_csv('data/streaming_transactions.csv', index=False)
    print(f"\n✅ Saved streaming dataset")
    
    # Step 4: Split FL data across banks for federated learning
    print("\n" + "=" * 70)
    print("🔀 SPLITTING FL DATA FOR FEDERATED NETWORK")
    print("=" * 70)
    
    bank_data = enricher.split_for_federated_learning(fl_initial_data)
    
    # Step 5: Initialize database and load FL initial data
    print("\n" + "=" * 70)
    print("💾 LOADING FL DATA INTO DUAL-INDEX SYSTEM")
    print("=" * 70)
    
    db = CyborgDB()
    
    for bank_name, data in bank_data.items():
        db.load_bank_data(bank_name, data)
    
    # Step 6: Display network statistics
    print("\n" + "=" * 70)
    print("📈 NETWORK STATISTICS")
    print("=" * 70)
    
    stats = db.get_network_stats()
    for bank, bank_stats in stats.items():
        print(f"\n{bank}:")
        print(f"   Normal Patterns Learned: {bank_stats['normal_patterns']}")
        print(f"   Known Threats: {bank_stats['known_threats']}")
    
    # Display streaming dataset info
    print("\n" + "=" * 70)
    print("📊 STREAMING DATASET STATISTICS")
    print("=" * 70)
    fraud_count = (streaming_data['isFraud'] == 1).sum()
    legit_count = (streaming_data['isFraud'] == 0).sum()
    print(f"Total Transactions: {len(streaming_data)}")
    print(f"   Legitimate: {legit_count} ({legit_count/len(streaming_data)*100:.1f}%)")
    print(f"   Fraudulent: {fraud_count} ({fraud_count/len(streaming_data)*100:.1f}%)")
    print(f"\nTransaction Types:")
    print(streaming_data['type'].value_counts())
    
    print("\n" + "=" * 70)
    print("✅ SYSTEM READY FOR FEDERATED OPERATIONS")
    print("=" * 70)
    print("\n💡 Next Steps:")
    print("   1. Start Kafka: docker-compose -f docker-compose-kafka.yml up -d")
    print("   2. Start Consumer: python streaming_consumer.py")
    print("   3. Start Producer: python streaming_producer.py")
    print("   4. Start FL Trainer: python fl_trainer.py")
    print("   5. Watch real transactions flow in real-time!")
    
    return db, bank_data, streaming_data


if __name__ == "__main__":
    db, bank_data = main()