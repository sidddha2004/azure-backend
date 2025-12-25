"""
STREAMING TRANSACTION CONSUMER
Consumes transactions from Kafka and processes them in real-time
Stores in CyborgDB dual-index architecture
"""

import json
import time
from kafka import KafkaConsumer
from database import CyborgDB
from typing import Dict
import uuid

class TransactionStreamConsumer:
    """
    Processes real-time transaction stream from Kafka
    """
    
    def __init__(self, kafka_bootstrap_servers='localhost:9092'):
        """Initialize Kafka consumer and CyborgDB"""
        print("🔌 Connecting to Kafka Consumer...")
        
        self.consumer = KafkaConsumer(
            'transactions',
            bootstrap_servers=kafka_bootstrap_servers,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            key_deserializer=lambda k: k.decode('utf-8') if k else None,
            auto_offset_reset='latest',  # Start from latest messages
            enable_auto_commit=True,
            group_id='fraud-detection-group'
        )
        
        print("🔌 Connecting to CyborgDB...")
        self.db = CyborgDB()
        
        # Statistics
        self.stats = {
            'total_processed': 0,
            'legitimate': 0,
            'fraud': 0,
            'blocked': 0,
            'by_bank': {'Bank A': 0, 'Bank B': 0, 'Bank C': 0},
            'start_time': time.time()
        }
        
        print("✅ Consumer Ready - Listening for transactions...\n")
    
    def process_transaction(self, transaction: Dict) -> Dict:
        """
        Process a single transaction through the fraud detection pipeline
        
        Returns detection result
        """
        txn_id = transaction.get('txn_id', str(uuid.uuid4()))
        description = transaction['description']
        amount = transaction['amount']
        bank = transaction['bank']
        user_id = transaction.get('user_id', 'system')
        is_fraud = transaction['is_fraud']
        
        # Store in appropriate index
        success = self.db.secure_storage(
            txn_id=txn_id,
            description=description,
            amount=amount,
            bank=bank,
            user_id=user_id,
            is_fraud=is_fraud
        )
        
        # Perform real-time risk assessment
        risk_result = self.assess_risk(description, amount, bank)
        
        # Update statistics
        self.update_stats(bank, is_fraud, risk_result)
        
        return {
            'txn_id': txn_id,
            'stored': success,
            'risk_level': risk_result['risk_level'],
            'action': risk_result['action']
        }
    
    def assess_risk(self, description: str, amount: float, bank: str) -> Dict:
        """
        Real-time risk assessment by querying both indexes
        """
        # Create vector
        query_vector = self.db.create_vector(description)
        
        # Check against secure_history (legitimate patterns)
        history_results = self.db.history_index.query(query_vectors=query_vector, top_k=5)
        history_distance = history_results[0].get('distance', 999) if history_results else 999
        
        # Check against known_threats (fraud patterns)
        threat_results = self.db.threats_index.query(query_vectors=query_vector, top_k=5)
        threat_distance = threat_results[0].get('distance', 999) if threat_results else 999
        
        # Calculate risk
        risk_level = self.db.calculate_risk(
            history_distance,
            threat_distance,
            amount,
            description,
            bank
        )
        
        # Determine action
        if "BLOCKED" in risk_level:
            action = "BLOCKED"
        elif "HIGH RISK" in risk_level:
            action = "FLAGGED"
        else:
            action = "APPROVED"
        
        return {
            'risk_level': risk_level,
            'action': action,
            'history_distance': history_distance,
            'threat_distance': threat_distance
        }
    
    def update_stats(self, bank: str, is_fraud: int, risk_result: Dict):
        """Update processing statistics"""
        self.stats['total_processed'] += 1
        
        if is_fraud == 1:
            self.stats['fraud'] += 1
        else:
            self.stats['legitimate'] += 1
        
        if risk_result['action'] == 'BLOCKED':
            self.stats['blocked'] += 1
        
        if bank in self.stats['by_bank']:
            self.stats['by_bank'][bank] += 1
    
    def print_stats(self):
        """Print current statistics"""
        elapsed = time.time() - self.stats['start_time']
        rate = self.stats['total_processed'] / elapsed if elapsed > 0 else 0
        
        print(f"\n{'='*70}")
        print(f"📊 REAL-TIME STATISTICS")
        print(f"{'='*70}")
        print(f"Total Processed: {self.stats['total_processed']}")
        print(f"  ✅ Legitimate: {self.stats['legitimate']}")
        print(f"  🚨 Fraud: {self.stats['fraud']}")
        print(f"  🚫 Blocked: {self.stats['blocked']}")
        print(f"\nBy Bank:")
        for bank, count in self.stats['by_bank'].items():
            print(f"  {bank}: {count}")
        print(f"\nProcessing Rate: {rate:.2f} txn/s")
        print(f"Uptime: {elapsed:.1f}s")
        print(f"{'='*70}\n")
    
    def start_consuming(self, print_interval: int = 10):
        """
        Start consuming and processing transactions
        
        Args:
            print_interval: Print stats every N transactions
        """
        print("="*70)
        print("🎧 LISTENING FOR TRANSACTIONS")
        print("="*70)
        print("Waiting for messages from Kafka...")
        print("💡 Press Ctrl+C to stop\n")
        
        try:
            for message in self.consumer:
                transaction = message.value
                
                # Process transaction
                result = self.process_transaction(transaction)
                
                # Log result
                action_emoji = {
                    'APPROVED': '✅',
                    'FLAGGED': '⚠️',
                    'BLOCKED': '🚫'
                }.get(result['action'], '❓')
                
                print(f"{action_emoji} [{transaction['bank']}] "
                      f"{transaction['description'][:50]} - "
                      f"${transaction['amount']:.2f} → {result['action']}")
                
                # Print stats periodically
                if self.stats['total_processed'] % print_interval == 0:
                    self.print_stats()
                    
        except KeyboardInterrupt:
            print("\n\n⏹️  Consumer stopped by user")
        
        finally:
            self.print_stats()
            self.consumer.close()
            print("✅ Consumer closed")


def main():
    """Main execution"""
    print("="*70)
    print("🔍 REAL-TIME FRAUD DETECTION CONSUMER")
    print("="*70)
    
    # Configuration
    KAFKA_SERVERS = 'localhost:9092'
    PRINT_INTERVAL = 10  # Print stats every 10 transactions
    
    # Create consumer
    consumer = TransactionStreamConsumer(kafka_bootstrap_servers=KAFKA_SERVERS)
    
    # Start consuming
    consumer.start_consuming(print_interval=PRINT_INTERVAL)


if __name__ == "__main__":
    main()