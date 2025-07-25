import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os # Para gestionar rutas

# --- 1. Cargar sus datos etiquetados ---
data_file = 'your_vulnerability_data.csv'
if not os.path.exists(data_file):
    print(f"Error: El archivo de datos '{data_file}' no fue encontrado. Asegúrese de crearlo y llenarlo.")
    exit()

df = pd.read_csv(data_file)

# Rellenar valores NaN en vulners_output con cadena vacía para evitar errores
df['vulners_output'] = df['vulners_output'].fillna('')
df['product_version'] = df['product_version'].fillna('')


# --- 2. Ingeniería de Características ---
# Función para extraer características de una fila de datos
def extract_features(row):
    port = int(row['port_number'])
    service_name = str(row['service_name']).lower()
    product_version = str(row['product_version']).lower()
    vulners_output = str(row['vulners_output']).lower()

    features = {
        'port_number': port,
        'is_common_web_port': 1 if port in [80, 443, 8080] else 0,
        'is_common_db_port': 1 if port in [3306, 5432, 1433] else 0,
        'is_common_ssh_port': 1 if port == 22 else 0,
        'is_common_ftp_port': 1 if port == 21 else 0,
        'is_common_telnet_port': 1 if port == 23 else 0,
        'service_apache': 1 if 'apache' in product_version or 'httpd' in service_name else 0,
        'service_openssh': 1 if 'openssh' in product_version or 'ssh' in service_name else 0,
        'service_microsoft_iis': 1 if 'iis' in product_version else 0,
        'service_ftp': 1 if 'ftp' in service_name else 0,
        'service_telnet': 1 if 'telnet' in service_name else 0,
        'service_mysql': 1 if 'mysql' in service_name else 0,
        'is_openssh_old': 1 if ('openssh' in product_version and any(v_prefix in product_version for v_prefix in ['5.','6.']) or ('7.' in product_version and 'p1' not in product_version and 'p2' not in product_version)) else 0,
        'is_apache_2_2': 1 if 'apache' in product_version and '2.2' in product_version else 0,
        'is_telnet_open_unencrypted': 1 if 'telnet' in service_name and 'ssl' not in product_version and port == 23 else 0, # Asumiendo Telnet en puerto 23 sin SSL
        'vulners_critical_found': 1 if 'critical' in vulners_output else 0,
        'vulners_high_found': 1 if 'high' in vulners_output else 0,
        'vulners_medium_found': 1 if 'medium' in vulners_output else 0,
        'vulners_low_found': 1 if 'low' in vulners_output else 0,
        'vulners_script_output_present': 1 if vulners_output else 0,
        'port_state_open': 1 # Asumimos que los datos son de puertos abiertos para el ML en este contexto
    }
    return features

# Aplicar la extracción de características a todo el DataFrame
features_list = df.apply(extract_features, axis=1).tolist()
features_df = pd.DataFrame(features_list)

# CRÍTICO: Guarda la lista de columnas para asegurar el orden en la predicción en la aplicación
# Esta lista debe ser copiada EXACTAMENTE en gui/screens.py como MASTER_FEATURES_LIST
master_features_list = features_df.columns.tolist()
print("--- Copie y pegue esta lista en gui/screens.py como 'MASTER_FEATURES_LIST' ---")
print(master_features_list)
print("--------------------------------------------------------------------------------")


# --- 3. Codificación de Etiquetas (Variables Objetivo) ---
# Convertir severidad textual a numérica
le_severity = LabelEncoder()
df['severity_encoded'] = le_severity.fit_transform(df['manual_severity'])
# Generar mapeo numérico a textual para usar en la aplicación
severity_numeric_to_text = {idx: label for idx, label in enumerate(le_severity.classes_)}
print("\n--- Mapeo de Severidad (Copie y pegue en gui/screens.py como 'NUMERIC_TO_SPANISH_SEVERITY') ---")
print(severity_numeric_to_text)
print("--------------------------------------------------------------------------------")

# Convertir recomendación textual a numérica
le_recommendation = LabelEncoder()
df['recommendation_encoded'] = le_recommendation.fit_transform(df['manual_recommendation'])
# Generar mapeo numérico a textual para usar en la aplicación
recommendation_numeric_to_text = {idx: label for idx, label in enumerate(le_recommendation.classes_)}
print("\n--- Mapeo de Recomendación (Copie y pegue en gui/screens.py como 'RECOMMENDATIONS_MAP') ---")
print(recommendation_numeric_to_text)
print("--------------------------------------------------------------------------------")


# --- 4. Preparación de X (Características) e Y (Etiquetas) ---
X = features_df # Las características para el entrenamiento
y_severity = df['severity_encoded'] # La variable objetivo para la severidad
y_recommendation = df['recommendation_encoded'] # La variable objetivo para la recomendación


# --- 5. División de Datos: Entrenamiento y Prueba ---
# Dividimos los datos para evaluar el rendimiento del modelo en datos no vistos
X_train_sev, X_test_sev, y_train_sev, y_test_sev = train_test_split(X, y_severity, test_size=0.2, random_state=42)
X_train_rec, X_test_rec, y_train_rec, y_test_rec = train_test_split(X, y_recommendation, test_size=0.2, random_state=42)


# --- 6. Entrenamiento de los Modelos de Clasificación ---
print("\nEntrenando modelo de clasificación de severidad...")
severity_model = RandomForestClassifier(n_estimators=100, random_state=42) # Usamos RandomForest como se menciona en el TFM
severity_model.fit(X_train_sev, y_train_sev)
print("Modelo de severidad entrenado.")

print("Entrenando modelo de clasificación de recomendaciones...")
recommendation_model = RandomForestClassifier(n_estimators=100, random_state=42) # Opcional: Entrenar un modelo para recomendaciones
recommendation_model.fit(X_train_rec, y_train_rec)
print("Modelo de recomendaciones entrenado.")


# --- 7. Evaluación del Rendimiento del Modelo (Opcional pero muy recomendado) ---
# Esto le dará una idea de qué tan bien funcionan sus modelos
from sklearn.metrics import classification_report, accuracy_score

print("\n--- Evaluación del Modelo de Severidad ---")
y_pred_sev = severity_model.predict(X_test_sev)
print(f"Precisión General (Severidad): {accuracy_score(y_test_sev, y_pred_sev):.2f}")
print(classification_report(y_test_sev, y_pred_sev, target_names=le_severity.classes_))

print("\n--- Evaluación del Modelo de Recomendaciones ---")
y_pred_rec = recommendation_model.predict(X_test_rec)
print(f"Precisión General (Recomendaciones): {accuracy_score(y_test_rec, y_pred_rec):.2f}")
print(classification_report(y_test_rec, y_pred_rec, target_names=le_recommendation.classes_))


# --- 8. Persistencia de los Modelos (Guardado) ---
# Guarde los modelos entrenados en archivos .pkl
# Estos archivos son los que la aplicación ScanIA cargará al inicio
joblib.dump(severity_model, 'severity_model.pkl')
joblib.dump(recommendation_model, 'recommendation_model.pkl')
print("\nModelos 'severity_model.pkl' y 'recommendation_model.pkl' guardados exitosamente en el directorio del proyecto.")