def analizar_archivo(ruta):
    # Simulación de análisis
    with open(ruta, 'r') as f:
        contenido = f.read()
    if 'eval(' in contenido:
        return 'Riesgo detectado: uso de eval'
    return 'Archivo limpio'
