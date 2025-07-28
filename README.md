# ScanIA - Análisis de Vulnerabilidades con Inteligencia Artificial

Este repositorio contiene el código fuente del proyecto de grado "Desarrollo de una herramienta para el análisis de vulnerabilidades en redes locales mediante inteligencia artificial".

## Características clave:
* Escaneo de red (Nmap)
* Clasificación de vulnerabilidades por IA (Scikit-learn)
* Generación de tratamientos/soluciones para vulnerabilidades.
* Interfaz gráfica amigable (Kivy)
* Generación de informes PDF.

## Cómo ejecutar el proyecto:

1.  **Clonar el repositorio:**
    `git clone https://github.com/metalin/ScanIA.git`
    `cd ScanIA`

2.  **Crear y activar el entorno virtual:**
    `python3 -m venv venv_scan_ia`
    `source venv_scan_ia/bin/activate`

3.  **Instalar dependencias:**
    `pip install -r requirements.txt`

4.  **Entrenar los modelos de IA:**
    `python train_ml_model.py`
    (Este paso generará `severity_model.pkl` y `treatment_model.pkl` y te dará las listas de mapeo para `screens.py`)

5.  **Copiar los mapeos a `gui/screens.py`:**
    Abre `gui/screens.py` y reemplaza las listas `NUMERIC_TO_SPANISH_SEVERITY`, `TREATMENT_SOLUTION_MAP` y `MASTER_FEATURES_LIST` con las que `train_ml_model.py` te proporcionó en la consola.

6.  **Ejecutar la aplicación:**
    `python main.py`
