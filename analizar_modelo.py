# analizar_modelo.py
# Este script carga los modelos entrenados y analiza la importancia de las características.

import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings

# Ignorar advertencias para una salida más limpia
warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=UserWarning)

def analizar_importancia(modelo, nombre_modelo):
    """Extrae, ordena y grafica la importancia de las características de un modelo."""
    
    print(f"\n--- Analizando la Importancia de Características para: {nombre_modelo} ---")

    # La lista de características debe ser la misma que se usó en el entrenamiento
    features = [
        'port_number', 'is_common_web_port', 'is_common_db_port', 'is_common_ssh_port',
        'is_common_ftp_port', 'is_common_telnet_port', 'service_apache', 'service_openssh',
        'service_microsoft_iis', 'service_ftp', 'service_telnet', 'service_mysql',
        'is_openssh_old', 'is_apache_2_2', 'is_telnet_open_unencrypted',
        'vulners_critical_found', 'vulners_high_found', 'vulners_medium_found',
        'vulners_low_found', 'vulners_script_output_present', 'port_state_open'
    ]
    
    # Extraer la importancia de las características del modelo
    importancias = modelo.feature_importances_
    
    # Crear un DataFrame para visualizar mejor
    df_importancia = pd.DataFrame({
        'Caracteristica': features,
        'Importancia': importancias
    }).sort_values(by='Importancia', ascending=False)

    print("Características más importantes según el modelo:")
    print(df_importancia)

    # --- Visualización ---
    plt.figure(figsize=(10, 8))
    sns.barplot(x='Importancia', y='Caracteristica', data=df_importancia, palette='rocket')
    plt.title(f'Importancia de Características - {nombre_modelo}', fontsize=16, weight='bold')
    plt.xlabel('Nivel de Importancia', fontsize=12)
    plt.ylabel('Característica', fontsize=12)
    plt.tight_layout()
    
    # Guardar el gráfico
    nombre_archivo = f'importancia_{nombre_modelo}.png'
    plt.savefig(nombre_archivo)
    print(f"\nGráfico de importancia guardado como '{nombre_archivo}'")
    
    return df_importancia

if __name__ == '__main__':
    try:
        # Cargar los modelos que ya entrenaste
        print("Cargando modelos 'severity_model.pkl' y 'treatment_model.pkl'...")
        severity_model = joblib.load('severity_model.pkl')
        treatment_model = joblib.load('treatment_model.pkl')
        print("Modelos cargados exitosamente.")
        
        # Analizar ambos modelos
        analizar_importancia(severity_model, 'Modelo_de_Severidad')
        analizar_importancia(treatment_model, 'Modelo_de_Tratamiento')

        print("\n----------------------------------------------------")
        print("✅ ¡Análisis completado!")
        print("Revisa los gráficos .png generados en esta carpeta.")
        print("----------------------------------------------------")

    except FileNotFoundError:
        print("\n\nError Crítico: No se encontraron los archivos 'severity_model.pkl' o 'treatment_model.pkl'.")
        print("Asegúrate de que este script esté en la misma carpeta que tus modelos ya entrenados.")
    except Exception as e:
        print(f"\n\nOcurrió un error inesperado durante el análisis: {e}")