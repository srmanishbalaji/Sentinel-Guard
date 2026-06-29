# ==========================================
# SENTINEL GUARD – PHASE 1 IMPLEMENTATION
# USB Malware Detection + Network Intrusion Detection
# Using Naive Bayes Classifier
# ==========================================

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import datetime
import random
import csv
import os

# ------------------------------
# 🔹 Preprocessing Helper Function
# ------------------------------
def preprocess_dataset(df, label_col):
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    X = df.drop(label_col, axis=1)
    y = df[label_col]
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, y


# ------------------------------
# 🧩 USB Malware Detection Module
# ------------------------------
def usb_detection():
    print("🧩 USB Malware Detection (CLaMP Dataset)")

    # Load the dataset
    df = pd.read_csv("C:\\Users\\LENOVO\\Documents\\Python Scripts\\SentinelGuard Final\\SentinelGuard\\data\\usb\\ClaMP_Integrated-5184.csv")

    # Rename the label for clarity
    df = df.rename(columns={'class': 'Malicious'})

    # Keep only numeric columns
    df = df.select_dtypes(include=[np.number]).dropna()

    # Split features and label
    X = df.drop('Malicious', axis=1)
    y = df['Malicious']

    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Random split for dynamic output
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=random.randint(0, 1000)
    )

    # Train Naive Bayes model
    model = GaussianNB()
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    # Evaluate performance
    acc = accuracy_score(y_test, y_pred)
    print(f"✅ USB Detection Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred))

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title("USB Malware Detection – Confusion Matrix (CLaMP)")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.show()

    return acc


# ------------------------------
# 🌐 Network Intrusion Detection Module
# ------------------------------
def network_detection():
    print("🌐 Network Intrusion Detection (UNSW-NB15 Dataset)")

    train = pd.read_csv("C:\\Users\\LENOVO\\Documents\\Python Scripts\\SentinelGuard Final\\SentinelGuard\\data\\network\\UNSW_NB15_training-set.csv")
    test = pd.read_csv("C:\\Users\\LENOVO\Documents\\Python Scripts\\SentinelGuard Final\\SentinelGuard\\data\\network\\UNSW_NB15_testing-set.csv")
    df = pd.concat([train, test], ignore_index=True)

    # Drop irrelevant or ID columns
    df = df.drop(columns=['id', 'srcip', 'sport', 'dstip', 'dsport', 'attack_cat'], errors='ignore')

    # Encode categorical columns
    for col in df.select_dtypes(include=['object']).columns:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])

    X, y = preprocess_dataset(df, 'label')

    # Random split for dynamic output
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=random.randint(0, 1000)
    )

    model = GaussianNB()
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"✅ Network Detection Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred))

    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Reds')
    plt.title("Network Intrusion Detection – Confusion Matrix (UNSW-NB15)")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.show()

    return acc


# ------------------------------
# 🪪 Logging Function (Enhanced)
# ------------------------------
def log_event(module, dataset, algorithm, accuracy):
    log_file = "sentinelguard_log.csv"

    # Create CSV header if file doesn't exist
    if not os.path.exists(log_file):
        with open(log_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Module", "Dataset", "Algorithm", "Status", "Accuracy"])

    # Append log entry
    with open(log_file, "a", newline="") as f:
        writer = csv.writer(f)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([timestamp, module, dataset, algorithm, "Completed", round(accuracy, 4)])

    print(f"🪪 {module} logged → Accuracy: {accuracy:.4f}")


# ------------------------------
# 🚀 MAIN EXECUTION
# ------------------------------
print("🚀 Sentinel Guard – Phase 1 Execution Started")

usb_acc = usb_detection()
log_event("USB Malware Detection", "CLaMP", "Gaussian Naive Bayes", usb_acc)

net_acc = network_detection()
log_event("Network Intrusion Detection", "UNSW-NB15", "Gaussian Naive Bayes", net_acc)

print("\n✅ Phase 1 completed – results saved in sentinelguard_log.csv\n")

# Display log entries neatly
log_files = pd.read_csv("sentinelguard_log.csv")
print(log_files.tail())