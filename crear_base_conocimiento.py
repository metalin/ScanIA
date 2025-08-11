# crear_base_conocimiento.py
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
import warnings

warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=UserWarning)

def crear_base_conocimiento(archivo_csv):
    print("--- INICIANDO LA CREACIÓN DE LA BASE DE CONOCIMIENTO ---")
    
    try:
        df = pd.read_csv(archivo_csv)
        print(f"[PASO 1/3] Datos crudos cargados desde '{archivo_csv}'.")
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{archivo_csv}'. Ejecuta primero 'generar_datos.py'.")
        return

    # --- Crear una 'firma' de texto para cada vulnerabilidad ---
    # Combinamos las columnas más importantes en un solo texto para cada fila.
    print("[PASO 2/3] Creando firmas de texto para cada vulnerabilidad...")
    df['signature'] = df['service_name'] + ' ' + df['product_version'] + ' ' + df['vulnerability_context_description']

    # --- Usar TF-IDF para vectorizar las firmas ---
    # Esto convierte cada texto en un conjunto de números que representan su importancia.
    vectorizer = TfidfVectorizer(min_df=2, max_features=500)
    
    # Aprender el vocabulario y crear la matriz de conocimiento
    knowledge_matrix = vectorizer.fit_transform(df['signature'])
    print("  - Matriz de conocimiento creada con éxito.")

    # --- Guardar todo en un único archivo ---
    # Guardamos el vectorizador (para traducir nuevas búsquedas)
    # la matriz (la base de conocimiento) y los datos originales para obtener las respuestas.
    knowledge_base = {
        'vectorizer': vectorizer,
        'knowledge_matrix': knowledge_matrix,
        'dataframe': df
    }
    
    output_file = 'knowledge_base.pkl'
    joblib.dump(knowledge_base, output_file)
    
    print(f"[PASO 3/3] ¡Éxito! Base de conocimiento guardada en '{output_file}'.")

if __name__ == '__main__':
    # Asegúrate de usar el archivo de datos generado más reciente
    crear_base_conocimiento('your_vulnerability_data_new.csv')