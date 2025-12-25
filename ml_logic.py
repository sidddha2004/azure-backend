import torch
import torch.nn as nn
import torch.optim as optim
import flwr as fl
import pandas as pd
import numpy as np
from collections import OrderedDict
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

# --- Configuration ---
DATA_PATH = "data/transactions.csv"  # Ensure this matches your file location
BATCH_SIZE = 64

class FraudNet(nn.Module):
    def __init__(self, input_shape):
        super(FraudNet, self).__init__()
        # Input features -> Hidden Layer -> Output (Fraud Probability)
        self.fc1 = nn.Linear(input_shape, 32)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.2)
        self.fc2 = nn.Linear(32, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out = self.fc1(x)
        out = self.relu(out)
        out = self.dropout(out)
        out = self.fc2(out)
        return self.sigmoid(out)

def load_real_data():
    """
    Loads PaySim CSV, preprocesses it, and returns PyTorch DataLoaders.
    """
    print(f"Loading dataset from {DATA_PATH}...")
    try:
        # Load only 10,000 rows for speed during dev
        df = pd.read_csv(DATA_PATH, nrows=10000) 
    except FileNotFoundError:
        print("ERROR: CSV not found. Using random noise for fallback.")
        return None, None, 6 # Fallback input size

    # --- Preprocessing ---
    # 1. Select relevant columns
    # type: CASH_OUT, PAYMENT, etc.
    # amount: transaction value
    # oldbalanceOrg: balance before txn
    # newbalanceOrig: balance after txn
    features = ['type', 'amount', 'oldbalanceOrg', 'newbalanceOrig']
    target = 'isFraud'

    X = df[features].copy()
    y = df[target]

    # 2. Encode Categorical Data ('type') -> Numbers
    le = LabelEncoder()
    X['type'] = le.fit_transform(X['type'])

    # 3. Normalize Numerical Data (Scale to 0-1 range)
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # 4. Split Train/Test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 5. Convert to PyTorch Tensors
    X_train_tensor = torch.tensor(X_train, dtype=torch.float32)
    y_train_tensor = torch.tensor(y_train.values, dtype=torch.float32).view(-1, 1)
    X_test_tensor = torch.tensor(X_test, dtype=torch.float32)
    y_test_tensor = torch.tensor(y_test.values, dtype=torch.float32).view(-1, 1)

    # 6. Create Loaders
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    test_dataset = TensorDataset(X_test_tensor, y_test_tensor)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE)

    return train_loader, test_loader, X.shape[1]

# --- Flower Client ---
class BankClient(fl.client.NumPyClient):
    def __init__(self, model, train_loader, test_loader):
        self.model = model
        self.train_loader = train_loader
        self.test_loader = test_loader

    def get_parameters(self, config):
        return [val.cpu().numpy() for _, val in self.model.state_dict().items()]

    def set_parameters(self, parameters):
        params_dict = zip(self.model.state_dict().keys(), parameters)
        state_dict = OrderedDict({k: torch.tensor(v) for k, v in params_dict})
        self.model.load_state_dict(state_dict, strict=True)

    def fit(self, parameters, config):
        self.set_parameters(parameters)
        criterion = nn.BCELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        self.model.train()
        
        for epoch in range(1): # Run 1 local epoch per federated round
            for data, target in self.train_loader:
                optimizer.zero_grad()
                output = self.model(data)
                loss = criterion(output, target)
                loss.backward()
                optimizer.step()
            
        return self.get_parameters(config={}), len(self.train_loader.dataset), {}

    def evaluate(self, parameters, config):
        self.set_parameters(parameters)
        self.model.eval()
        loss, correct = 0, 0
        criterion = nn.BCELoss()
        
        with torch.no_grad():
            for data, target in self.test_loader:
                output = self.model(data)
                loss += criterion(output, target).item()
                predicted = (output > 0.5).float()
                correct += (predicted == target).sum().item()
        
        accuracy = correct / len(self.test_loader.dataset)
        return float(loss), len(self.test_loader.dataset), {"accuracy": accuracy}

def start_federated_client():
    train_loader, test_loader, input_dim = load_real_data()
    
    # Fallback for demo if no CSV
    if train_loader is None:
        return "Error: No CSV found. Please add backend/data/transactions.csv"

    model = FraudNet(input_dim)
    
    try:
        fl.client.start_client(
            server_address="127.0.0.1:8080", 
            client=BankClient(model, train_loader, test_loader).to_client()
        )
        return "Training Round Complete on Real Data"
    except Exception as e:
        print(f"FEDERATED ERROR: {e}") 
        return f"Connection Failed: {str(e)}"