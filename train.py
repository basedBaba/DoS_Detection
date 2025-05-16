import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import make_pipeline
import joblib
from time import time
import matplotlib.pyplot as plt
import seaborn as sns

# 🔹 Load your dataset
df = pd.read_csv("C:/Users/saile/OneDrive/Desktop/000/filtered_dataset.csv")

print(f"\n📊 Dataset loaded with {len(df):,} entries")
print("Class distribution:")
print(df['result'].value_counts())

# 🔹 Target: Convert to binary (0 = normal, 1 = attack)
df['is_attack'] = df['result'].apply(lambda x: 0 if x.strip() == 'normal.' else 1)

# 🔹 Features to use
features = [
    'protocol_type', 'service', 'flag',
    'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment'
]

# 🔹 Separate categorical and numerical columns
categorical_cols = ['protocol_type', 'service', 'flag']
numerical_cols = ['duration', 'src_bytes', 'dst_bytes', 'wrong_fragment']

# 🔹 Preprocessing pipeline
preprocessor = ColumnTransformer([
    ('num', StandardScaler(), numerical_cols),
    ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols)
])

# 🔹 Prepare input/output
X = df[features]
y = df['is_attack']

# 🔹 Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# 🔹 SMOTE if needed
if y_train.value_counts().min() < 1000:
    smote = SMOTE(random_state=42)
else:
    smote = None

# 🔹 Pipeline builder
def create_pipeline(model):
    steps = [('preprocessor', preprocessor)]
    if smote:
        steps.append(('smote', smote))
    steps.append(('classifier', model))
    return Pipeline(steps)

# 🔹 Random Forest
print("\n🌲 Training Random Forest...")
rf_pipeline = create_pipeline(RandomForestClassifier(
    n_estimators=200,
    max_depth=30,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced_subsample'
))
start = time()
rf_pipeline.fit(X_train, y_train)
print(f"Trained in {time() - start:.2f}s")

# 🔹 Gradient Boosting
print("\n🚀 Training Gradient Boosting...")
gb_pipeline = create_pipeline(GradientBoostingClassifier(
    n_estimators=200,
    learning_rate=0.05,
    max_depth=5,
    random_state=42
))
start = time()
gb_pipeline.fit(X_train, y_train)
print(f"Trained in {time() - start:.2f}s")

# 🔹 Neural Network
print("\n🧠 Training Neural Network...")
ann_pipeline = create_pipeline(MLPClassifier(
    hidden_layer_sizes=(128, 64, 32),
    activation='relu',
    solver='adam',
    batch_size=256,
    learning_rate='adaptive',
    max_iter=200,
    early_stopping=True,
    validation_fraction=0.1,
    random_state=42
))
start = time()
ann_pipeline.fit(X_train, y_train)
print(f"Trained in {time() - start:.2f}s")

# 🔹 Save models
joblib.dump(rf_pipeline, 'rf_pipeline.pkl')
joblib.dump(gb_pipeline, 'gb_pipeline.pkl')
joblib.dump(ann_pipeline, 'ann_pipeline.pkl')

# 🔹 Evaluation function
def evaluate_model(model, X_test, y_test, model_name):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    print(f"\n🔍 {model_name} Evaluation:")
    print(classification_report(y_test, y_pred))
    print(f"ROC AUC Score: {roc_auc_score(y_test, y_proba):.4f}")
    
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title(f'{model_name} Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.show()

# 🔹 Evaluate all models
evaluate_model(rf_pipeline, X_test, y_test, "Random Forest")
evaluate_model(gb_pipeline, X_test, y_test, "Gradient Boosting")
evaluate_model(ann_pipeline, X_test, y_test, "Neural Network")

print("\n✅ All models trained, evaluated, and saved!")
