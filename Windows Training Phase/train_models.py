import os
import json
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


DATASET_PATH = "output/ids_dataset.csv"
MODEL_DIR = "models"

LABEL_MAPPING = {
    0: "Normal",
    1: "Ping DoS",
    2: "SYN Flood",
    3: "Nmap Scan",
    4: "Brute Force",
}


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    df = pd.read_csv(DATASET_PATH)

    print("Dataset loaded successfully")
    print("Shape:", df.shape)
    print("\nLabel distribution:")
    print(df["label"].value_counts())

    if "traffic_type" in df.columns:
        df = df.drop(columns=["traffic_type"])

    X = df.drop(columns=["label"])
    y = df["label"]

    feature_columns = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced"
        ),
        "Decision Tree": DecisionTreeClassifier(
            random_state=42,
            class_weight="balanced",
            max_depth=8
        ),
        "SVM": Pipeline([
            ("scaler", StandardScaler()),
            ("model", SVC(kernel="rbf", class_weight="balanced", probability=True))
        ]),
        "KNN": Pipeline([
            ("scaler", StandardScaler()),
            ("model", KNeighborsClassifier(n_neighbors=5))
        ]),
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=3000, class_weight="balanced"))
        ]),
    }

    best_model_name = None
    best_model = None
    best_score = 0

    results = {}

    for name, model in models.items():
        print("\n" + "=" * 60)
        print(f"Training: {name}")

        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        results[name] = acc

        print(f"Accuracy: {acc:.4f}")
        print("\nClassification Report:")
        print(classification_report(
            y_test,
            y_pred,
            target_names=[LABEL_MAPPING[i] for i in sorted(LABEL_MAPPING.keys())]
        ))

        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

        safe_name = name.lower().replace(" ", "_")
        joblib.dump(model, os.path.join(MODEL_DIR, f"{safe_name}.pkl"))

        if acc > best_score:
            best_score = acc
            best_model_name = name
            best_model = model

    joblib.dump(best_model, os.path.join(MODEL_DIR, "best_ids_model.pkl"))
    joblib.dump(feature_columns, os.path.join(MODEL_DIR, "feature_columns.pkl"))

    with open(os.path.join(MODEL_DIR, "label_mapping.json"), "w") as f:
        json.dump(LABEL_MAPPING, f, indent=4)

    print("\n" + "=" * 60)
    print("Training completed")
    print("Model results:")
    for name, score in results.items():
        print(f"{name}: {score:.4f}")

    print(f"\nBest model: {best_model_name}")
    print(f"Best accuracy: {best_score:.4f}")

    print("\nSaved files:")
    print("models/best_ids_model.pkl")
    print("models/feature_columns.pkl")
    print("models/label_mapping.json")


if __name__ == "__main__":
    main()