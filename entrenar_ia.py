# entrenar_ia.py
# Este script unificado procesa los datos y entrena los modelos en un solo paso.

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import warnings

# Ignorar advertencias para una salida más limpia
warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=UserWarning)


def procesar_datos(archivo_csv):
    """Carga y transforma los datos crudos en un formato listo para ML."""
    print("[PASO 1/5] Cargando y procesando datos crudos...")
    
    df = pd.read_csv(archivo_csv)

    # --- Mapeo de Soluciones (Tratamiento) ---
    solution_map = {solution: i for i, solution in enumerate(df['proposed_treatment_solution'].unique())}
    df['treatment_id'] = df['proposed_treatment_solution'].map(solution_map)
    print("  - Mapeo de soluciones (tratamiento) creado.")
    
    # --- Mapeo de Severidad ---
    # Usamos un orden lógico para la severidad
    severity_order = ['Info', 'Low', 'Medium', 'High', 'Critical']
    # Filtramos para asegurarnos de que solo mapeamos valores presentes en los datos
    present_severities = [s for s in severity_order if s in df['manual_severity'].unique()]
    severity_map = {severity: i for i, severity in enumerate(present_severities)}
    df['severity_id'] = df['manual_severity'].map(severity_map)
    print("  - Mapeo de severidad creado.")

    # --- Creación de Características (Feature Engineering) ---
    def create_features(row):
        port = row['port_number']
        service = str(row['service_name']).lower()
        product = str(row['product_version']).lower()
        vulners = str(row['vulners_output']).lower()
        
        features = {
            'is_common_web_port': 1 if port in [80, 443, 8080] else 0,
            'is_common_db_port': 1 if port in [3306, 5432, 1433] else 0,
            'is_common_ssh_port': 1 if port == 22 else 0,
            'is_common_ftp_port': 1 if port == 21 else 0,
            'is_common_telnet_port': 1 if port == 23 else 0,
            'service_apache': 1 if 'apache' in product or 'http' in service else 0,
            'service_openssh': 1 if 'openssh' in product or 'ssh' in service else 0,
            'service_microsoft_iis': 1 if 'iis' in product else 0,
            'service_ftp': 1 if 'ftp' in service else 0,
            'service_telnet': 1 if 'telnet' in service else 0,
            'service_mysql': 1 if 'mysql' in service else 0,
            'is_openssh_old': 1 if 'openssh' in product and any(v in product for v in ['5.','6.','7.0','7.1','7.2','7.3']) else 0,
            'is_apache_2_2': 1 if 'apache' in product and '2.2' in product else 0,
            'is_telnet_open_unencrypted': 1 if 'telnet' in service else 0,
            'vulners_critical_found': 1 if 'critical' in vulners else 0,
            'vulners_high_found': 1 if 'high' in vulners else 0,
            'vulners_medium_found': 1 if 'medium' in vulners else 0,
            'vulners_low_found': 1 if 'low' in vulners else 0,
            'vulners_script_output_present': 1 if vulners and "simulated" in vulners else 0,
            'port_state_open': 1
        }
        # La característica 'port_number' se mantiene como estaba
        features_with_port = {'port_number': port, **features}
        return pd.Series(features_with_port)

    feature_df = df.apply(create_features, axis=1)
    df_ml = pd.concat([df[['severity_id', 'treatment_id']], feature_df], axis=1)
    
    print(f"  - ¡Procesamiento completado! ({len(df_ml.columns)} columnas listas para IA)")
    return df_ml


def entrenar_modelos(df_ml):
    """Entrena, evalúa y guarda los modelos de IA."""
    
    # --- Preparación de Datos: Definir Características (X) y Objetivos (y) ---
    print("\n[PASO 2/5] Preparando datos para el entrenamiento...")
    features = [
        'port_number', 'is_common_web_port', 'is_common_db_port', 'is_common_ssh_port',
        'is_common_ftp_port', 'is_common_telnet_port', 'service_apache', 'service_openssh',
        'service_microsoft_iis', 'service_ftp', 'service_telnet', 'service_mysql',
        'is_openssh_old', 'is_apache_2_2', 'is_telnet_open_unencrypted',
        'vulners_critical_found', 'vulners_high_found', 'vulners_medium_found',
        'vulners_low_found', 'vulners_script_output_present', 'port_state_open'
    ]
    
    X = df_ml[features]
    y_severity = df_ml['severity_id']
    y_treatment = df_ml['treatment_id']
    
    X_train, X_test, y_sev_train, y_sev_test, y_treat_train, y_treat_test = train_test_split(
        X, y_severity, y_treatment, test_size=0.2, random_state=42, stratify=y_treatment
    )
    print("  - Datos divididos en conjuntos de entrenamiento (80%) y prueba (20%).")

    # --- Entrenamiento del Modelo de Severidad ---
    print("\n[PASO 3/5] Entrenando el modelo de SEVERIDAD...")
    severity_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    severity_model.fit(X_train, y_sev_train)
    print("  - ¡Modelo de severidad entrenado!")

    # --- Entrenamiento del Modelo de Tratamiento ---
    print("\n[PASO 4/5] Entrenando el modelo de TRATAMIENTO...")
    treatment_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    treatment_model.fit(X_train, y_treat_train)
    print("  - ¡Modelo de tratamiento entrenado!")

    # --- Evaluación y Guardado de Modelos ---
    print("\n[PASO 5/5] Evaluando rendimiento y guardando los modelos...")
    
    sev_predictions = severity_model.predict(X_test)
    print("\n--- INFORME DE RENDIMIENTO (SEVERIDAD) ---")
    print(classification_report(y_sev_test, sev_predictions))

    treat_predictions = treatment_model.predict(X_test)
    print("\n--- INFORME DE RENDIMIENTO (TRATAMIENTO) ---")
    print(classification_report(y_treat_test, treat_predictions))
    
    joblib.dump(severity_model, 'severity_model.pkl')
    joblib.dump(treatment_model, 'treatment_model.pkl')


if __name__ == '__main__':
    print("--- INICIANDO PROCESO COMPLETO DE ENTRENAMIENTO DE IA ---")
    try:
        # Ejecutar ambos pasos en secuencia
        datos_listos = procesar_datos('your_vulnerability_data.csv')
        entrenar_modelos(datos_listos)
        
        print("\n----------------------------------------------------")
        print("✅ ¡Entrenamiento completado exitosamente!")
        print("Se han guardado dos archivos en esta carpeta:")
        print("  - severity_model.pkl")
        print("  - treatment_model.pkl")
        print("¡Ya puedes copiarlos a tu aplicación ScanIA!")
        print("----------------------------------------------------")

    except FileNotFoundError:
        print("\n\nError Crítico: No se encontró el archivo 'your_vulnerability_data.csv'.")
        print("Asegúrate de que este script esté en la misma carpeta que tu archivo de datos.")
    except Exception as e:
        print(f"\n\nOcurrió un error inesperado durante el proceso: {e}")