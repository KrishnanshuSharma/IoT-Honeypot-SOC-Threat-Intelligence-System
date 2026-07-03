import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# --- 1. CONFIGURATION ---
CSV_FILE = '/home/adminn/iot_project/dataset.csv'
MODEL_FILE = '/home/adminn/iot_project/rf_model.pkl'

def train_model():
    print("==========================================")
    print("[*] Initiating Artificial Intelligence Training...")
    print("==========================================")

    # --- 2. LOAD THE DATASET ---
    try:
        df = pd.read_csv('master_dataset.csv')
        print(f"[+] Loaded dataset with {len(df)} network packets.")
    except FileNotFoundError:
        print(f"[!] Error: Could not find {CSV_FILE}.")
        return

    # --- 3. PREPARE THE DATA ---
    # X contains the mathematical features, y contains the answer (the label)
    X = df.drop('label', axis=1)
    y = df['label']

    # Split the data: 80% to train the AI, 20% to test its accuracy
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"[+] Split complete: {len(X_train)} training samples, {len(X_test)} testing samples.")

    # --- 4. TRAIN THE RANDOM FOREST ---
    print("[*] Training Random Forest Classifier (100 Trees)...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # --- 5. EVALUATE THE AI ---
    print("[*] Evaluating accuracy on unseen test data...")
    predictions = clf.predict(X_test)
    
    acc = accuracy_score(y_test, predictions)
    print(f"\n[+] AI ACCURACY SCORE: {acc * 100:.2f}%\n")
    
    print("[*] Detailed Threat Classification Report:")
    print(classification_report(y_test, predictions, zero_division=0))

    # --- 6. SAVE THE BRAIN ---
    with open(MODEL_FILE, 'wb') as f:
        pickle.dump(clf, f)
    
    print("==========================================")
    print(f"[+] AI Brain saved successfully to: {MODEL_FILE}")
    print("[+] The system is now ready for Real-Time live defense.")
    print("==========================================")

if __name__ == "__main__":
    train_model()
