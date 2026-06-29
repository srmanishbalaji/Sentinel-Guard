# ==========================================
# SENTINEL GUARD – PHASE 1 DASHBOARD (Streamlit)
# USB Malware Detection + Network Intrusion Detection
# ==========================================

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import seaborn as sns
import matplotlib.pyplot as plt

# --- Streamlit Page Setup ---
st.set_page_config(page_title="Sentinel Guard – Phase 1", page_icon="🛡️", layout="wide")

# --- Custom Styling (Dark Cyber Theme) ---
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
        color: #FAFAFA;
    }
    .stTabs [role="tablist"] button {
        background-color: #1e2130;
        color: #FAFAFA;
        border-radius: 10px;
        margin-right: 8px;
    }
    .stTabs [role="tablist"] button[aria-selected="true"] {
        background-color: #0073e6;
        color: white;
    }
    h1, h2, h3 {
        color: #33C3F0;
    }
    </style>
""", unsafe_allow_html=True)

# --- Title ---
st.title("🛡️ SENTINEL GUARD – AI Enabled Hybrid Firewall (Phase 1)")
st.markdown("### USB Malware Detection + Network Intrusion Detection using Gaussian Naive Bayes")

# --- Tabs for Modules ---
tab1, tab2 = st.tabs(["💽 USB Malware Detection", "🌐 Network Intrusion Detection"])

# ==========================================
# USB MALWARE DETECTION MODULE
# ==========================================
with tab1:
    st.subheader("💽 USB Malware Detection (CLaMP Dataset)")
    uploaded_file = st.file_uploader("Upload USB Malware Dataset (CSV)", type="csv", key="usb")

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.write("### Dataset Preview")
        st.dataframe(df.head())

        if 'class' not in df.columns:
            st.error("❌ The dataset must include a 'class' column as label.")
        else:
            df = df.select_dtypes(include=[np.number]).dropna()
            X = df.drop('class', axis=1)
            y = df['class']

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

            model = GaussianNB()
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)

            # Metrics
            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, average='weighted')
            rec = recall_score(y_test, y_pred, average='weighted')
            f1 = f1_score(y_test, y_pred, average='weighted')

            st.write("### 📊 Model Performance Metrics")
            st.metric("Accuracy", f"{acc*100:.2f}%")
            st.metric("Precision", f"{prec*100:.2f}%")
            st.metric("Recall", f"{rec*100:.2f}%")
            st.metric("F1-Score", f"{f1*100:.2f}%")

            # Confusion Matrix
            cm = confusion_matrix(y_test, y_pred)
            fig, ax = plt.subplots()
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax)
            ax.set_title("Confusion Matrix – USB Malware Detection")
            ax.set_xlabel("Predicted")
            ax.set_ylabel("Actual")
            st.pyplot(fig)

            # Classification Report
            st.write("### 🧾 Classification Report")
            st.text(classification_report(y_test, y_pred))
    else:
        st.info("📥 Upload your USB malware dataset to begin detection.")


# ==========================================
# NETWORK INTRUSION DETECTION MODULE
# ==========================================
with tab2:
    st.subheader("🌐 Network Intrusion Detection (UNSW-NB15 Dataset)")
    uploaded_file2 = st.file_uploader("Upload Network Intrusion Dataset (CSV)", type="csv", key="network")

    if uploaded_file2 is not None:
        df = pd.read_csv(uploaded_file2)
        st.write("### Dataset Preview")
        st.dataframe(df.head())

        if 'label' not in df.columns:
            st.error("❌ The dataset must include a 'label' column as target.")
        else:
            df = df.drop(columns=['id','srcip','sport','dstip','dsport','attack_cat'], errors='ignore')
            for col in df.select_dtypes(include=['object']).columns:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col])

            X = df.drop('label', axis=1)
            y = df['label']

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

            model = GaussianNB()
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)

            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, average='weighted')
            rec = recall_score(y_test, y_pred, average='weighted')
            f1 = f1_score(y_test, y_pred, average='weighted')

            st.write("### 📊 Model Performance Metrics")
            st.metric("Accuracy", f"{acc*100:.2f}%")
            st.metric("Precision", f"{prec*100:.2f}%")
            st.metric("Recall", f"{rec*100:.2f}%")
            st.metric("F1-Score", f"{f1*100:.2f}%")

            cm = confusion_matrix(y_test, y_pred)
            fig, ax = plt.subplots()
            sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', ax=ax)
            ax.set_title("Confusion Matrix – Network Intrusion Detection")
            ax.set_xlabel("Predicted")
            ax.set_ylabel("Actual")
            st.pyplot(fig)

            st.write("### 🧾 Classification Report")
            st.text(classification_report(y_test, y_pred))
    else:
        st.info("📥 Upload your network intrusion dataset to start detection.")
