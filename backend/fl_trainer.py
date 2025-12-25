"""
FEDERATED LEARNING TRAINER
Performs periodic federated learning rounds across banks
Extracts patterns from recent transactions and aggregates globally
"""

import time
from typing import Dict, List
from database import CyborgDB
from datetime import datetime, timedelta
import numpy as np

class FederatedLearner:
    """
    Coordinates federated learning rounds across multiple banks
    """
    
    def __init__(self):
        """Initialize FL coordinator"""
        print("🤖 Initializing Federated Learning System...")
        self.db = CyborgDB()
        self.banks = ['Bank A', 'Bank B', 'Bank C']
        self.round_number = 0
        self.global_accuracy = 0.82  # Starting baseline
        
        # Track learning history
        self.learning_history = {
            'rounds': [],
            'accuracies': [],
            'patterns_learned': []
        }
        
        print("✅ FL System Ready\n")
    
    def extract_local_patterns(self, bank: str, time_window_minutes: int = 60) -> Dict:
        """
        Extract fraud patterns from a bank's recent transactions
        
        This simulates local model training without sharing raw data
        """
        print(f"   📚 Extracting patterns from {bank}...")
        
        # Time threshold
        time_threshold = time.time() - (time_window_minutes * 60)
        
        # Query recent fraud patterns from this bank
        fraud_query = self.db.create_vector("fraud suspicious unauthorized illegal")
        
        # Search threats index for recent patterns
        results = self.db.threats_index.query(query_vectors=fraud_query, top_k=100)
        
        # Filter by bank and time
        recent_patterns = []
        for res in results:
            meta = res.get('metadata', {})
            if meta.get('bank') == bank and meta.get('timestamp', 0) > time_threshold:
                recent_patterns.append({
                    'description': meta.get('description'),
                    'vector': res.get('vector'),
                    'amount': meta.get('amount'),
                    'pattern_type': meta.get('pattern_type')
                })
        
        # Extract pattern statistics (simulates gradient computation)
        pattern_stats = {
            'bank': bank,
            'num_patterns': len(recent_patterns),
            'avg_amount': np.mean([p['amount'] for p in recent_patterns]) if recent_patterns else 0,
            'pattern_types': list(set([p.get('pattern_type', 'UNKNOWN') for p in recent_patterns])),
            'patterns': recent_patterns[:10]  # Send top 10 patterns
        }
        
        print(f"      ✅ Found {len(recent_patterns)} new fraud patterns")
        return pattern_stats
    
    def aggregate_patterns(self, local_updates: List[Dict]) -> Dict:
        """
        Aggregate patterns from all banks (FedAvg-style)
        
        This simulates secure aggregation without exposing individual bank data
        """
        print("\n   🔄 Aggregating patterns globally...")
        
        # Collect all patterns
        all_patterns = []
        total_patterns = 0
        
        for update in local_updates:
            all_patterns.extend(update['patterns'])
            total_patterns += update['num_patterns']
        
        # Deduplicate patterns by semantic similarity
        unique_patterns = self.deduplicate_patterns(all_patterns)
        
        # Calculate global statistics
        global_update = {
            'total_patterns': total_patterns,
            'unique_patterns': len(unique_patterns),
            'participating_banks': len(local_updates),
            'patterns': unique_patterns
        }
        
        print(f"      ✅ Aggregated {total_patterns} patterns into {len(unique_patterns)} unique threats")
        return global_update
    
    def deduplicate_patterns(self, patterns: List[Dict]) -> List[Dict]:
        """
        Remove duplicate patterns using semantic similarity
        """
        if not patterns:
            return []
        
        unique = []
        seen_descriptions = set()
        
        for pattern in patterns:
            desc = pattern['description']
            # Simple deduplication by exact description
            # In production, would use vector similarity
            if desc not in seen_descriptions:
                seen_descriptions.add(desc)
                unique.append(pattern)
        
        return unique
    
    def distribute_global_update(self, global_update: Dict):
        """
        Distribute learned patterns to all banks' threat indexes
        
        This simulates model redistribution in FL
        """
        print("\n   📤 Distributing global update to all banks...")
        
        patterns_to_add = []
        
        for pattern in global_update['patterns']:
            # Create threat record for each bank
            for bank in self.banks:
                vector = pattern.get('vector')
                if vector:
                    threat_record = {
                        'id': f"fl_round_{self.round_number}_{bank}_{pattern['description'][:20]}",
                        'vector': vector,
                        'metadata': {
                            'description': pattern['description'],
                            'amount': pattern['amount'],
                            'bank': bank,
                            'user_id': 'federated_learner',
                            'timestamp': time.time(),
                            'is_fraud': 1,
                            'threat_level': 'HIGH',
                            'fl_round': self.round_number,
                            'learned_globally': True
                        }
                    }
                    patterns_to_add.append(threat_record)
        
        # Batch upsert to known_threats
        if patterns_to_add:
            self.db.threats_index.upsert(patterns_to_add)
            print(f"      ✅ Distributed {len(patterns_to_add)} patterns across {len(self.banks)} banks")
    
    def simulate_accuracy_improvement(self, num_patterns: int) -> float:
        """
        Simulate accuracy improvement based on patterns learned
        
        In production, this would be actual model evaluation
        """
        # Logarithmic improvement (diminishing returns)
        improvement = min(0.05, num_patterns * 0.001)
        self.global_accuracy = min(0.99, self.global_accuracy + improvement)
        return self.global_accuracy
    
    def perform_fl_round(self, time_window_minutes: int = 60):
        """
        Perform one complete federated learning round
        
        Args:
            time_window_minutes: Look at patterns from last N minutes
        """
        self.round_number += 1
        
        print("\n" + "="*70)
        print(f"🚀 FEDERATED LEARNING ROUND #{self.round_number}")
        print("="*70)
        print(f"Time Window: Last {time_window_minutes} minutes")
        print(f"Participating Banks: {', '.join(self.banks)}\n")
        
        start_time = time.time()
        
        # STEP 1: Local Pattern Extraction (parallel in production)
        print("📊 PHASE 1: Local Pattern Extraction")
        print("-" * 70)
        local_updates = []
        for bank in self.banks:
            update = self.extract_local_patterns(bank, time_window_minutes)
            local_updates.append(update)
        
        # STEP 2: Global Aggregation
        print("\n📊 PHASE 2: Secure Aggregation")
        print("-" * 70)
        global_update = self.aggregate_patterns(local_updates)
        
        # STEP 3: Distribution
        print("\n📊 PHASE 3: Global Distribution")
        print("-" * 70)
        self.distribute_global_update(global_update)
        
        # STEP 4: Evaluation
        print("\n📊 PHASE 4: Evaluation")
        print("-" * 70)

        old_accuracy = self.global_accuracy
        new_accuracy = self.simulate_accuracy_improvement(global_update['unique_patterns'])
        delta = new_accuracy - old_accuracy

        # Record history
        self.learning_history['rounds'].append(self.round_number)
        self.learning_history['accuracies'].append(new_accuracy)
        self.learning_history['patterns_learned'].append(global_update['unique_patterns'])

        elapsed = time.time() - start_time

        # Summary
        print(f"\n{'='*70}")
        print(f"✅ ROUND #{self.round_number} COMPLETE")
        print(f"{'='*70}")
        print(f"Duration: {elapsed:.2f}s")
        print(f"Patterns Learned: {global_update['unique_patterns']}")
        print(f"Global Accuracy: {new_accuracy:.2%} (↑ {delta:.2%})")
        print(f"All Banks Updated: ✅")
        print(f"{'='*70}\n")

        
        return {
            'round_id': f"FL-{self.round_number:04d}",
            'accuracy': new_accuracy,
            'patterns_learned': global_update['unique_patterns'],
            'duration': elapsed
        }
    
    def continuous_learning(self, interval_minutes: int = 60):
        """
        Run continuous federated learning rounds
        
        Args:
            interval_minutes: Time between FL rounds
        """
        print("="*70)
        print("🔄 CONTINUOUS FEDERATED LEARNING ENABLED")
        print("="*70)
        print(f"Round Interval: Every {interval_minutes} minutes")
        print("💡 Press Ctrl+C to stop\n")
        
        try:
            while True:
                # Perform FL round
                result = self.perform_fl_round(time_window_minutes=interval_minutes)
                
                # Wait for next round
                print(f"⏳ Next round in {interval_minutes} minutes...\n")
                time.sleep(interval_minutes * 60)
                
        except KeyboardInterrupt:
            print("\n\n⏹️  Continuous learning stopped")
            self.print_summary()
    
    def print_summary(self):
        """Print learning summary"""
        if not self.learning_history['rounds']:
            return
        
        print(f"\n{'='*70}")
        print(f"📈 FEDERATED LEARNING SUMMARY")
        print(f"{'='*70}")
        print(f"Total Rounds: {self.round_number}")
        print(f"Starting Accuracy: {self.learning_history['accuracies'][0]:.2%}")
        print(f"Final Accuracy: {self.learning_history['accuracies'][-1]:.2%}")
        print(f"Total Patterns Learned: {sum(self.learning_history['patterns_learned'])}")
        print(f"{'='*70}\n")


def main():
    """Main execution"""
    print("="*70)
    print("🤖 FEDERATED LEARNING COORDINATOR")
    print("="*70)
    
    # Create FL coordinator
    fl = FederatedLearner()
    
    # Run continuous learning (every 60 minutes)
    # For testing, set to 5 minutes
    INTERVAL_MINUTES = 5
    
    fl.continuous_learning(interval_minutes=INTERVAL_MINUTES)


if __name__ == "__main__":
    main()