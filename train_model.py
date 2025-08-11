# train_model.py

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

print("--- INICIANDO EL ENTRENAMIENTO DE MODELOS DE IA ---")

# --- 1. Carga de Datos ---
try:
    df = pd.read_csv('vulnerability_data_ML.csv')
    print(f"[PASO 1/5] Datos cargados exitosamente desde 'vulnerability_data_ML.csv'. ({len(df)} filas)")
except FileNotFoundError:
    print("Error: No se encontró el archivo 'vulnerability_data_ML.csv'.")
    print("Asegúrate de que este script esté en la misma carpeta que tu archivo de datos.")
    exit()

# --- 2. Preparación de Datos: Definir Características (X) y Objetivos (y) ---
print("[PASO 2/5] Preparando datos para el entrenamiento...")

# Las características son todas las columnas que describen la vulnerabilidad
# Esta lista debe coincidir con MASTER_FEATURES_LIST en tu app de Kivy
features = [
    'port_number', 'is_common_web_port', 'is_common_db_port', 'is_common_ssh_port',
    'is_common_ftp_port', 'is_common_telnet_port', 'service_apache', 'service_openssh',
    'service_microsoft_iis', 'service_ftp', 'service_telnet', 'service_mysql',
    'is_openssh_old', 'is_apache_2_2', 'is_telnet_open_unencrypted',
    'vulners_critical_found', 'vulners_high_found', 'vulners_medium_found',
    'vulners_low_found', 'vulners_script_output_present', 'port_state_open'
]

X = df[features]
y_severity = df['severity_id']
y_treatment = df['treatment_id']

# Dividir los datos: 80% para entrenar, 20% para probar
X_train, X_test, y_sev_train, y_sev_test, y_treat_train, y_treat_test = train_test_split(
    X, y_severity, y_treatment, test_size=0.2, random_state=42, stratify=y_treatment
)
print("Datos divididos en conjuntos de entrenamiento (80%) y prueba (20%).")

# --- 3. Entrenamiento del Modelo de Severidad ---
print("\n[PASO 3/5] Entrenando el modelo de SEVERIDAD...")
severity_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
severity_model.fit(X_train, y_sev_train)
print("¡Modelo de severidad entrenado!")

# --- 4. Entrenamiento del Modelo de Tratamiento ---
print("\n[PASO 4/5] Entrenando el modelo de TRATAMIENTO...")
treatment_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
treatment_model.fit(X_train, y_treat_train)
print("¡Modelo de tratamiento entrenado!")

# --- 5. Evaluación y Guardado de Modelos ---
print("\n[PASO 5/5] Evaluando rendimiento y guardando los modelos...")

# Evaluar modelo de Severidad
sev_predictions = severity_model.predict(X_test)
print("\n--- INFORME DE RENDIMIENTO (SEVERIDAD) ---")
print(classification_report(y_sev_test, sev_predictions))

# Evaluar modelo de Tratamiento
treat_predictions = treatment_model.predict(X_test)
print("\n--- INFORME DE RENDIMIENTO (TRATAMIENTO) ---")
print(classification_report(y_treat_test, treat_predictions))

# Guardar los modelos entrenados
joblib.dump(severity_model, 'severity_model.pkl')
joblib.dump(treatment_model, 'treatment_model.pkl')

print("\n----------------------------------------------------")
print("✅ ¡Entrenamiento completado exitosamente!")
print("Se han guardado dos archivos en esta carpeta:")
print("  - severity_model.pkl")
print("  - treatment_model.pkl")
print("----------------------------------------------------")