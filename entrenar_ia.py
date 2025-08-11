# entrenar_ia.py
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import warnings
import json

warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=UserWarning)

def procesar_datos(archivo_csv):
    print("[PASO 1/5] Cargando y procesando datos crudos...")
    df = pd.read_csv(archivo_csv)
    solution_map = {solution: i for i, solution in enumerate(df['proposed_treatment_solution'].unique())}
    df['treatment_id'] = df['proposed_treatment_solution'].map(solution_map)
    severity_order = ['Info', 'Low', 'Medium', 'High', 'Critical']
    present_severities = [s for s in severity_order if s in df['manual_severity'].unique()]
    severity_map = {severity: i for i, severity in enumerate(present_severities)}
    df['severity_id'] = df['manual_severity'].map(severity_map)

    def create_features(row):
        port = row['port_number']
        service = str(row['service_name']).lower()
        product = str(row['product_version']).lower()
        vulners = str(row['vulners_output']).lower()
        return pd.Series({
            'service_apache': 1 if 'apache' in product or 'http' in service else 0,
            'service_openssh': 1 if 'openssh' in product or 'ssh' in service else 0,
            'service_cctv': 1 if any(kw in service for kw in ['rtsp', 'dahua', 'hikvision']) else 0,
            'is_telnet_open_unencrypted': 1 if 'telnet' in service else 0,
            'vulners_critical_found': 1 if 'critical' in vulners else 0,
            'vulners_high_found': 1 if 'high' in vulners else 0,
            'vulners_medium_found': 1 if 'medium' in vulners else 0,
            'vulners_low_found': 1 if 'low' in vulners else 0,
            'vulners_info_found': 1 if 'info' in vulners else 0,
            'vulners_script_output_present': 1 if vulners and "simulated" in vulners else 0,
            'port_state_open': 1
        })
    feature_df = df.apply(create_features, axis=1)
    df['port_number'] = df['port_number'].astype('category')
    port_dummies = pd.get_dummies(df['port_number'], prefix='port')
    df_ml = pd.concat([df[['severity_id', 'treatment_id']], feature_df, port_dummies], axis=1)
    
    port_columns = list(port_dummies.columns)
    with open('model_maps.json', 'w') as f:
        json.dump({'solutions': solution_map, 'severities': severity_map, 'port_columns': port_columns}, f, indent=4)
    print("  - ¡Procesamiento completado y 'model_maps.json' guardado!")
    return df_ml

def entrenar_modelos(df_ml):
    print("\n[PASO 2/5] Preparando datos y características especializadas...")
    with open('model_maps.json', 'r') as f:
        port_columns = json.load(f)['port_columns']

    features_severity = ['vulners_critical_found', 'vulners_high_found', 'vulners_medium_found', 'vulners_low_found', 'vulners_info_found', 'vulners_script_output_present']
    features_treatment = ['service_apache', 'service_openssh', 'service_cctv', 'is_telnet_open_unencrypted', 'port_state_open'] + port_columns

    X_sev, y_sev = df_ml[features_severity], df_ml['severity_id']
    X_treat, y_treat = df_ml[features_treatment], df_ml['treatment_id']
    
    X_sev_train, X_sev_test, y_sev_train, y_sev_test = train_test_split(X_sev, y_sev, test_size=0.2, random_state=42, stratify=y_sev)
    X_treat_train, X_treat_test, y_treat_train, y_treat_test = train_test_split(X_treat, y_treat, test_size=0.2, random_state=42, stratify=y_treat)
    
    print("\n[PASO 3/5] Entrenando modelo de SEVERIDAD...")
    severity_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced').fit(X_sev_train, y_sev_train)
    
    print("\n[PASO 4/5] Entrenando modelo de TRATAMIENTO...")
    treatment_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced').fit(X_treat_train, y_treat_train)
    
    print("\n[PASO 5/5] Evaluando y guardando modelos...")
    print("\n--- INFORME DE RENDIMIENTO (SEVERIDAD) ---")
    print(classification_report(y_sev_test, severity_model.predict(X_sev_test), zero_division=0))
    print("\n--- INFORME DE RENDIMIENTO (TRATAMIENTO) ---")
    print(classification_report(y_treat_test, treatment_model.predict(X_treat_test), zero_division=0))
    
    joblib.dump(severity_model, 'severity_model.pkl')
    joblib.dump(treatment_model, 'treatment_model.pkl')

if __name__ == '__main__':
    try:
        datos_listos = procesar_datos('your_vulnerability_data_new.csv')
        entrenar_modelos(datos_listos)
        print("\n✅ ¡Entrenamiento completado!")
    except Exception as e:
        print(f"\n\nOcurrió un error: {e}")