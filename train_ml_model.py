import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os

print("--- train_ml_model.py: Script iniciado ---") # DEBUG: Confirma que el script empieza a ejecutarse

# --- 1. Cargar sus datos etiquetados ---
# ¡ATENCIÓN!: Asegúrese de que 'your_vulnerability_data.csv' exista en la misma carpeta que este script
# y que contenga sus datos de vulnerabilidades con las columnas especificadas.
data_file = 'your_vulnerability_data.csv'
if not os.path.exists(data_file):
    print(f"Error: El archivo de datos '{data_file}' no fue encontrado.")
    print("Por favor, cree este archivo CSV con sus datos de entrenamiento y las siguientes columnas:")
    print("ip_address,port_number,service_name,product_version,vulners_output,vulnerability_context_description,manual_severity,proposed_treatment_solution")
    print("Consulte la guía para más detalles sobre cómo crear este archivo.")
    exit()

print(f"Cargando datos desde {data_file}...") # DEBUG
df = pd.read_csv(data_file)
print(f"Datos cargados. Filas: {len(df)}") # DEBUG


# Rellenar valores NaN con cadena vacía para evitar errores de procesamiento
df['vulners_output'] = df['vulners_output'].fillna('')
df['product_version'] = df['product_version'].fillna('')
df['vulnerability_context_description'] = df['vulnerability_context_description'].fillna('')
df['proposed_treatment_solution'] = df['proposed_treatment_solution'].fillna('')

print("Valores nulos rellenados.") # DEBUG


# --- 2. Ingeniería de Características ---
# Esta función define las características de entrada para sus modelos ML.
# Debe ser un reflejo exacto de la lógica de _extract_features_for_ml en gui/screens.py
def extract_features(row):
    # print(f"DEBUG: Procesando fila para extract_features. Puerto: {row['port_number']}") # DEBUG: Para depurar procesamiento de filas
    # Extracción segura de datos con valores por defecto
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
        'is_telnet_open_unencrypted': 1 if 'telnet' in service_name and 'ssl' not in product_version and port == 23 else 0,
        'vulners_critical_found': 1 if 'critical' in vulners_output else 0,
        'vulners_high_found': 1 if 'high' in vulners_output else 0,
        'vulners_medium_found': 1 if 'medium' in vulners_output else 0,
        'vulners_low_found': 1 if 'low' in vulners_output else 0,
        'vulners_script_output_present': 1 if vulners_output else 0,
        'port_state_open': 1
    }
    return features

print("Extrayendo características para el entrenamiento...") # DEBUG
features_list = df.apply(extract_features, axis=1).tolist()
features_df = pd.DataFrame(features_list)
print("Características extraídas.") # DEBUG

# CRÍTICO: Imprime la lista de columnas para asegurar el orden en la predicción en la aplicación.
# Copia y pega esta lista EXACTAMENTE en gui/screens.py como MASTER_FEATURES_LIST
print("\n--- Copie y pegue esta lista en gui/screens.py como 'MASTER_FEATURES_LIST' ---")
print(features_df.columns.tolist())
print("--------------------------------------------------------------------------------")


# --- 3. Codificación de Etiquetas (Variables Objetivo para los modelos ML) ---
print("Codificando etiquetas de severidad y tratamiento...") # DEBUG

# 3.1. Para Severidad
le_severity = LabelEncoder()
df['manual_severity'] = df['manual_severity'].astype(str) # Asegurar tipo string
df['severity_encoded'] = le_severity.fit_transform(df['manual_severity'])
severity_numeric_to_text = {idx: label for idx, label in enumerate(le_severity.classes_)}
print("\n--- Mapeo de Severidad (Copie y pegue en gui/screens.py como 'NUMERIC_TO_SPANISH_SEVERITY') ---")
print(severity_numeric_to_text)
print("--------------------------------------------------------------------------------")

# 3.2. Para la Solución/Tratamiento Propuesto
le_treatment = LabelEncoder()
df['proposed_treatment_solution'] = df['proposed_treatment_solution'].astype(str) # Asegurar tipo string
df['treatment_encoded'] = le_treatment.fit_transform(df['proposed_treatment_solution'])
treatment_numeric_to_text = {idx: label for idx, label in enumerate(le_treatment.classes_)}
print("\n--- Mapeo de Solución/Tratamiento (Copie y pegue en gui/screens.py como 'TREATMENT_SOLUTION_MAP') ---")
print(treatment_numeric_to_text)
print("--------------------------------------------------------------------------------")

print("Etiquetas codificadas.") # DEBUG


# --- 4. Preparación de X (Características) e Y (Etiquetas) ---
X = features_df # Las características para el entrenamiento
y_severity = df['severity_encoded'] # La variable objetivo para la severidad
y_treatment = df['treatment_encoded'] # La variable objetivo para el tratamiento


# --- 5. División de Datos: Entrenamiento y Prueba ---
print("Dividiendo datos en conjuntos de entrenamiento y prueba...") # DEBUG
# Dividimos los datos para evaluar el rendimiento del modelo en datos no vistos
X_train_sev, X_test_sev, y_train_sev, y_test_sev = train_test_split(X, y_severity, test_size=0.2, random_state=42)
X_train_treat, X_test_treat, y_train_treat, y_test_treat = train_test_split(X, y_treatment, test_size=0.2, random_state=42)
print("Datos divididos.") # DEBUG


# --- 6. Entrenamiento de los Modelos de Clasificación ---
print("\nEntrenando modelo de clasificación de severidad...") # DEBUG
severity_model = RandomForestClassifier(n_estimators=100, random_state=42)
severity_model.fit(X_train_sev, y_train_sev)
print("Modelo de severidad entrenado.") # DEBUG

print("Entrenando modelo de clasificación de soluciones/tratamientos...") # DEBUG
treatment_model = RandomForestClassifier(n_estimators=100, random_state=42)
treatment_model.fit(X_train_treat, y_train_treat)
print("Modelo de soluciones/tratamientos entrenado.") # DEBUG


# --- 7. Evaluación del Rendimiento del Modelo ---
print("\nEvaluando rendimiento de los modelos...") # DEBUG
from sklearn.metrics import classification_report, accuracy_score
        
print("\n--- Evaluación del Modelo de Severidad ---")
y_pred_sev = severity_model.predict(X_test_sev)
print(f"Precisión General (Severidad): {accuracy_score(y_test_sev, y_pred_sev):.2f}")
print(classification_report(y_test_sev, y_pred_sev, target_names=le_severity.classes_))

print("\n--- Evaluación del Modelo de Soluciones/Tratamientos ---")
y_pred_treat = treatment_model.predict(X_test_treat)
print(f"Precisión General (Soluciones/Tratamientos): {accuracy_score(y_test_treat, y_pred_treat):.2f}")
print(classification_report(y_test_treat, y_pred_treat, target_names=le_treatment.classes_))
print("Evaluación completada.") # DEBUG


# --- 8. Persistencia de los Modelos (Guardado) ---
print("\nGuardando modelos...") # DEBUG
joblib.dump(severity_model, 'severity_model.pkl')
joblib.dump(treatment_model, 'treatment_model.pkl')
print("Modelos 'severity_model.pkl' y 'treatment_model.pkl' guardados exitosamente en el directorio del proyecto.") # DEBUG
print("--- train_ml_model.py: Script finalizado ---") # DEBUG