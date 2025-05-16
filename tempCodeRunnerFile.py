import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from time import time

# 1. Load and prepare data
print("Loading dataset...")
df = pd.read_csv('revised_kddcup_dataset.csv')
print(f"Original dataset size: {len(df):,}")

# 2. Feature engineering
features = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'count', 'srv_count',
    'same_srv_rate', 'diff_srv_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate'
]

# Create byte ratio feature
df['bytes_ratio'] = df['src_bytes'] / (df['dst_bytes'] + 1)
features.append('bytes_ratio')

# 3. Preprocessing
print("\nPreprocessing data...")
start = time()

# Encode categoricals
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    joblib.dump(le, f'{col}_encoder.pkl')

# Target variable - create dummy normal traffic if none exists
if 'normal' not in df['result'].unique():
    print("\n⚠️ No normal traffic found! Creating synthetic samples...")
    sample_size = min(10000, len(df))  # Create up to 10k normal samples
    normal_samples = df.sample(sample_size, random_state=42).copy()
    normal_samples['result'] = 'normal'
    normal_samples['src_bytes'] = normal_samples['src_bytes'] * 0.1  # Make smaller
    normal_samples['dst_bytes'] = normal_samples['dst_bytes'] * 0.1
    df = pd.concat([df, normal_samples])

df['is_attack'] = df['result'].apply(lambda x: 0 if x == 'normal' else 1)

# 4. Handle class distribution
X = df[features]
y = df['is_attack']

print("\nFinal class distribution:")
print(y.value_counts())

# 5. Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, 
    test_size=0.2, 
    random_state=42,
    stratify=y
)

# Scale features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)
joblib.dump(scaler, 'scaler.pkl')

print(f"\nPreprocessing completed in {time()-start:.2f} seconds")

# 6. Train Random Forest
print("\nTraining Random Forest...")
start = time()
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=30,
    min_samples_split=5,
    class_weight='balanced_subsample',
    n_jobs=-1,
    random_state=42
)
rf.fit(X_train, y_train)
print(f"Training completed in {time()-start:.2f} seconds")

# 7. Train Neural Network
print("\nTraining Neural Network...")
start = time()
ann = MLPClassifier(
    hidden_layer_sizes=(150, 100, 50),
    activation='relu',
    solver='adam',
    alpha=0.001,
    batch_size=512,
    learning_rate='adaptive',
    early_stopping=True,
    random_state=42
)
ann.fit(X_train, y_train)
print(f"Training completed in {time()-start:.2f} seconds")

# 8. Save models
joblib.dump(rf, 'rf_model.pkl')
joblib.dump(ann, 'ann_model.pkl')

# 9. Evaluation
def evaluate_model(name, model, X_test, y_test):
    y_pred = model.predict(X_test)
    print(f"\n{name} Performance:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Calculate accuracy
    accuracy = np.mean(y_pred == y_test)
    print(f"Accuracy: {accuracy:.4f}")

evaluate_model("Random Forest", rf, X_test, y_test)
evaluate_model("Neural Network", ann, X_test, y_test)

print("\n✅ Training complete! Models saved to disk.")