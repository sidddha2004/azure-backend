"""
DATA ENRICHMENT MODULE
Transforms raw PaySim transaction data into semantically rich descriptions
for vector search and federated learning.
"""

import random
import pandas as pd
from typing import Dict, List, Tuple

class TransactionEnricher:
    """
    Enriches raw transaction data with realistic semantic descriptions
    based on transaction type, amount, and fraud status.
    """
    
    def __init__(self):
        # Merchant categories by transaction type and amount range
        self.enrichment_rules = {
            'PAYMENT': {
                'small': [  # $0-50
                    "Starbucks Coffee Purchase",
                    "Uber Ride Payment",
                    "McDonald's Fast Food",
                    "Subway Sandwich Shop",
                    "Local Convenience Store",
                    "Dunkin Donuts Purchase",
                    "Movie Theater Ticket",
                    "Spotify Subscription Payment"
                ],
                'medium': [  # $50-500
                    "Shell Gas Station Fuel",
                    "Target Store Shopping",
                    "Walmart Grocery Purchase",
                    "Best Buy Electronics",
                    "Home Depot Hardware",
                    "Nike Store Apparel",
                    "Restaurant Dinner Payment",
                    "Hotel Accommodation Booking"
                ],
                'large': [  # $500+
                    "Apple Store MacBook Purchase",
                    "Furniture Store Payment",
                    "Jewelry Store Purchase",
                    "High-End Electronics Store",
                    "Luxury Hotel Extended Stay",
                    "Premium Appliance Purchase"
                ]
            },
            'TRANSFER': {
                'small': [
                    "Peer-to-Peer Venmo Transfer",
                    "Family Support Payment",
                    "Friend Reimbursement",
                    "Small Personal Transfer"
                ],
                'medium': [
                    "Monthly Rent Payment",
                    "Family Financial Support",
                    "Contractor Service Payment",
                    "Tuition Fee Payment",
                    "Insurance Premium Transfer"
                ],
                'large': [
                    "Real Estate Down Payment",
                    "Investment Transfer",
                    "Large Business Payment",
                    "Property Purchase Payment"
                ]
            },
            'CASH_OUT': {
                'small': [
                    "ATM Cash Withdrawal",
                    "Bank Branch Cash Out",
                    "Small Cash Advance"
                ],
                'medium': [
                    "Large ATM Withdrawal",
                    "Cash for Business Expenses",
                    "Emergency Cash Withdrawal"
                ],
                'large': [
                    "Bulk Cash Withdrawal",
                    "Large Business Cash Out"
                ]
            },
            'DEBIT': {
                'small': [
                    "Bill Payment Debit",
                    "Utility Bill Automatic Payment",
                    "Credit Card Auto Payment"
                ],
                'medium': [
                    "Mortgage Payment Debit",
                    "Large Utility Bill",
                    "Tax Payment Debit"
                ],
                'large': [
                    "Large Tax Payment",
                    "Major Bill Settlement"
                ]
            },
            'CASH_IN': {
                'small': [
                    "Salary Direct Deposit",
                    "Freelance Payment Received",
                    "Small Refund Credit"
                ],
                'medium': [
                    "Monthly Salary Deposit",
                    "Bonus Payment Received",
                    "Tax Refund Deposit"
                ],
                'large': [
                    "Large Contract Payment",
                    "Investment Return Deposit",
                    "Major Settlement Received"
                ]
            }
        }
        
        # Fraud patterns by transaction type
        self.fraud_patterns = {
            'PAYMENT': [
                "Card Testing Verification Charge",
                "Unauthorized Online Purchase",
                "Stolen Card Dark Web Merchant",
                "Fraud Ring Purchase Pattern",
                "Suspicious Multiple Small Charges"
            ],
            'TRANSFER': [
                "Offshore Shell Corporation Transfer",
                "Money Laundering Layering Transfer",
                "Suspicious Foreign Account Transfer",
                "Structuring Smurfing Pattern",
                "Terrorist Financing Suspected Transfer"
            ],
            'CASH_OUT': [
                "ATM Withdrawal Stolen Card",
                "Rapid Cash Out Fraud Pattern",
                "Suspicious Sequential Withdrawals",
                "Card Skimming Cash Out",
                "Identity Theft Cash Withdrawal"
            ],
            'DEBIT': [
                "Unauthorized Account Debit",
                "Fraudulent Bill Payment",
                "Suspicious Recurring Charge"
            ],
            'CASH_IN': [
                "Suspicious Cash Deposit Pattern",
                "Structuring Cash In",
                "Money Laundering Cash Deposit"
            ]
        }
    
    def get_amount_category(self, amount: float) -> str:
        """Categorize transaction amount into small/medium/large"""
        if amount < 50:
            return 'small'
        elif amount < 500:
            return 'medium'
        else:
            return 'large'
    
    def enrich_transaction(self, txn_type: str, amount: float, is_fraud: int) -> str:
        """
        Generate realistic semantic description based on transaction attributes
        
        Args:
            txn_type: Transaction type (PAYMENT, TRANSFER, etc.)
            amount: Transaction amount
            is_fraud: 1 if fraudulent, 0 if legitimate
            
        Returns:
            Enriched semantic description
        """
        # Round amount to 2 decimal places for cleaner display
        amount = round(amount, 2)
        
        # Handle fraud cases
        if is_fraud == 1:
            if txn_type in self.fraud_patterns:
                description = random.choice(self.fraud_patterns[txn_type])
                # Add amount context for better vector matching
                if amount > 100000:
                    description += f" Large Amount ${amount:,.2f}"
                elif amount < 10:
                    description += f" Micro Amount ${amount:.2f}"
                return description
            else:
                return f"Suspicious {txn_type} Transaction ${amount:,.2f}"
        
        # Handle legitimate transactions
        if txn_type not in self.enrichment_rules:
            return f"{txn_type} Transaction ${amount:,.2f}"
        
        amount_category = self.get_amount_category(amount)
        
        # Get appropriate merchant list
        if amount_category in self.enrichment_rules[txn_type]:
            merchant = random.choice(self.enrichment_rules[txn_type][amount_category])
            return f"{merchant} ${amount:,.2f}"
        else:
            return f"{txn_type} Transaction ${amount:,.2f}"
    
    def enrich_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Enrich entire dataset with semantic descriptions
        
        Args:
            df: DataFrame with columns: type, amount, isFraud
            
        Returns:
            DataFrame with added 'enriched_description' column
        """
        print("🔄 Enriching dataset with semantic descriptions...")
        
        df['enriched_description'] = df.apply(
            lambda row: self.enrich_transaction(
                row['type'], 
                row['amount'], 
                row['isFraud']
            ), 
            axis=1
        )
        
        print(f"✅ Enriched {len(df)} transactions")
        return df
    
    def split_for_federated_learning(
        self, 
        df: pd.DataFrame, 
        split_ratios: Dict[str, float] = None
    ) -> Dict[str, pd.DataFrame]:
        """
        Split enriched dataset for federated learning simulation
        
        Args:
            df: Enriched DataFrame
            split_ratios: Distribution per bank (default: equal split)
            
        Returns:
            Dictionary mapping bank names to their data subsets
        """
        if split_ratios is None:
            split_ratios = {
                'Bank A': 0.35,
                'Bank B': 0.35,
                'Bank C': 0.30
            }
        
        # Shuffle dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        banks = {}
        start_idx = 0
        
        for bank, ratio in split_ratios.items():
            size = int(len(df) * ratio)
            end_idx = start_idx + size
            banks[bank] = df.iloc[start_idx:end_idx].copy()
            
            # Add bank identifier
            banks[bank]['bank'] = bank
            
            print(f"📦 {bank}: {len(banks[bank])} transactions")
            print(f"   - Legitimate: {(banks[bank]['isFraud'] == 0).sum()}")
            print(f"   - Fraudulent: {(banks[bank]['isFraud'] == 1).sum()}")
            
            start_idx = end_idx
        
        return banks


# Example usage and testing
if __name__ == "__main__":
    # Create sample data (simulating PaySim format)
    sample_data = pd.DataFrame({
        'type': ['PAYMENT', 'PAYMENT', 'TRANSFER', 'TRANSFER', 'CASH_OUT', 'PAYMENT'],
        'amount': [12.50, 65.00, 500.00, 900000.00, 200.00, 3.00],
        'isFraud': [0, 0, 0, 1, 1, 1]
    })
    
    enricher = TransactionEnricher()
    enriched = enricher.enrich_dataset(sample_data)
    
    print("\n📊 Sample Enriched Transactions:")
    print(enriched[['type', 'amount', 'isFraud', 'enriched_description']])