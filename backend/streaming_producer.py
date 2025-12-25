"""
STREAMING TRANSACTION PRODUCER
Reads from real PaySim dataset and streams transactions in real-time
Simulates replay of actual transaction history across multiple banks
"""

import json
import time
import random
import pandas as pd
from datetime import datetime
from kafka import KafkaProducer

class TransactionStreamProducer:
    """
    Streams real transactions from PaySim dataset to Kafka
    """
    
    def __init__(self, dataset_path='data/streaming_transactions.csv', 
                 kafka_bootstrap_servers='localhost:9092'):
        """Initialize Kafka producer and load streaming dataset"""
        print("🔌 Connecting to Kafka...")
        
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            key_serializer=lambda k: k.encode('utf-8') if k else None
        )
        
        print(f"📂 Loading streaming dataset from {dataset_path}...")
        try:
            self.dataset = pd.read_csv(dataset_path)
            print(f"✅ Loaded {len(self.dataset)} transactions")
            
            # Display dataset statistics
            fraud_count = (self.dataset['isFraud'] == 1).sum()
            legit_count = (self.dataset['isFraud'] == 0).sum()
            print(f"   Legitimate: {legit_count} ({legit_count/len(self.dataset)*100:.1f}%)")
            print(f"   Fraudulent: {fraud_count} ({fraud_count/len(self.dataset)*100:.1f}%)")
            
        except FileNotFoundError:
            print(f"❌ Dataset not found at {dataset_path}")
            print("   Please run: python data_loader.py first")
            raise
        
        # Randomly assign transactions to banks for federated simulation
        self.banks = ['Bank A', 'Bank B', 'Bank C']
        self.dataset['assigned_bank'] = [random.choice(self.banks) for _ in range(len(self.dataset))]
        
        self.current_index = 0
        self.transaction_count = 0
        self.loop_count = 0
        
        print("✅ Kafka Producer Ready")
    
    def get_next_transaction(self) -> dict:
        """Get next transaction from dataset (loops when reaching end)"""
        
        # Loop back to start if we've processed all transactions
        if self.current_index >= len(self.dataset):
            self.current_index = 0
            self.loop_count += 1
            print(f"\n🔄 Dataset loop #{self.loop_count} - Replaying transactions...\n")
        
        # Get current row
        row = self.dataset.iloc[self.current_index]
        self.current_index += 1
        
        # Convert to transaction format
        transaction = {
            'txn_id': f"{row['assigned_bank'][:1]}{self.transaction_count:08d}",
            'type': row['type'],
            'amount': float(row['amount']),
            'bank': row['assigned_bank'],
            'is_fraud': int(row['isFraud']),
            'description': row['enriched_description'],
            'timestamp': datetime.now().isoformat(),
            'user_id': f"user_{random.randint(1, 100)}",
            'original_index': self.current_index - 1  # For debugging
        }
        
        self.transaction_count += 1
        return transaction
    
    def send_transaction(self, transaction: dict):
        """Send transaction to Kafka topic"""
        try:
            bank = transaction['bank']
            
            # Send to Kafka (partitioned by bank for parallel processing)
            future = self.producer.send(
                'transactions',
                key=bank,
                value=transaction
            )
            
            # Wait for confirmation
            future.get(timeout=10)
            
            # Log transaction
            fraud_emoji = "🚨" if transaction['is_fraud'] == 1 else "✅"
            print(f"{fraud_emoji} [{bank}] {transaction['description'][:60]} - ${transaction['amount']:.2f}")
            
        except Exception as e:
            print(f"❌ Error sending transaction: {e}")
    
    def start_streaming(self, transactions_per_second: float = 2.0, 
                       duration_seconds: int = 0, replay: bool = True):
        """
        Start streaming transactions from dataset
        
        Args:
            transactions_per_second: Rate of transaction streaming
            duration_seconds: How long to stream (0 = until dataset exhausted or infinite if replay=True)
            replay: If True, loop dataset continuously. If False, stop after one pass.
        """
        print("\n" + "="*70)
        print("🚀 STARTING REAL TRANSACTION STREAM")
        print("="*70)
        print(f"Rate: {transactions_per_second} transactions/second")
        print(f"Dataset Size: {len(self.dataset)} transactions")
        print(f"Replay Mode: {'Enabled (loops infinitely)' if replay else 'Disabled (one pass)'}")
        print(f"Duration: {'Infinite' if duration_seconds == 0 and replay else f'{duration_seconds}s' if duration_seconds > 0 else 'Until dataset exhausted'}")
        print(f"Banks: {', '.join(self.banks)}")
        print("="*70 + "\n")
        
        interval = 1.0 / transactions_per_second
        start_time = time.time()
        
        try:
            while True:
                # Check duration
                if duration_seconds > 0 and (time.time() - start_time) > duration_seconds:
                    break
                
                # Check if we've exhausted dataset (only if replay is False)
                if not replay and self.current_index >= len(self.dataset):
                    print("\n✅ Dataset exhausted - Streaming complete")
                    break
                
                # Get next transaction from dataset
                transaction = self.get_next_transaction()
                
                # Send to Kafka
                self.send_transaction(transaction)
                
                # Wait for next transaction
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n⏹️  Stream stopped by user")
        
        finally:
            elapsed = time.time() - start_time
            print(f"\n{'='*70}")
            print(f"📊 STREAM STATISTICS")
            print(f"{'='*70}")
            print(f"Total Transactions Sent: {self.transaction_count}")
            print(f"Dataset Loops: {self.loop_count}")
            print(f"Duration: {elapsed:.1f}s")
            print(f"Average Rate: {self.transaction_count/elapsed:.2f} txn/s")
            
            # Fraud statistics
            fraud_sent = sum(1 for i in range(self.transaction_count) 
                           if i < len(self.dataset) and self.dataset.iloc[i % len(self.dataset)]['isFraud'] == 1)
            print(f"Fraudulent Transactions: {fraud_sent} ({fraud_sent/self.transaction_count*100:.1f}%)")
            print(f"{'='*70}\n")
            
            self.producer.close()
            print("✅ Producer closed")


def main():
    """Main execution"""
    print("="*70)
    print("💳 REAL-TIME TRANSACTION STREAM PRODUCER (PaySim Dataset)")
    print("="*70)
    
    # Configuration
    DATASET_PATH = 'data/streaming_transactions.csv'
    KAFKA_SERVERS = 'localhost:9092'
    TRANSACTIONS_PER_SECOND = 0.5  # Slower: 1 transaction every 2 seconds
    DURATION = 0  # 0 = infinite with replay
    REPLAY = True  # Loop dataset continuously
    
    # Create producer
    try:
        producer = TransactionStreamProducer(
            dataset_path=DATASET_PATH,
            kafka_bootstrap_servers=KAFKA_SERVERS
        )
    except FileNotFoundError:
        print("\n❌ ERROR: Streaming dataset not found!")
        print("Please run the following command first:")
        print("   python data_loader.py")
        print("\nThis will create data/streaming_transactions.csv")
        return
    
    # Start streaming
    print("\n💡 Press Ctrl+C to stop streaming\n")
    time.sleep(2)
    
    producer.start_streaming(
        transactions_per_second=TRANSACTIONS_PER_SECOND,
        duration_seconds=DURATION,
        replay=REPLAY
    )


if __name__ == "__main__":
    main()