# -*- coding: utf-8 -*-

# 1. Configuración de Kivy (debe ir antes de otros imports de Kivy si es posible)
from kivy.config import Config
# Se restablece el tamaño inicial a 1200x800 como en tu archivo original
Config.set('graphics', 'width', '1200')  # Ancho inicial de la ventana en píxeles
Config.set('graphics', 'height', '800')   # Altura inicial de la ventana en píxeles
Config.set('graphics', 'resizable', True) # Permitir que la ventana sea redimensionable

# 2. Imports necesarios de Kivy y de tu proyecto
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager

# Asumiendo que DashboardScreen está definido en gui/screens.py
# Esta ruta de importación debe coincidir con la estructura de tu proyecto.
from gui.screens import DashboardScreen

# 3. Definición de la clase principal de la aplicación
class AnalisisVulnerabilidadesApp(App): # Puedes cambiar "AnalisisVulnerabilidadesApp" por el nombre que prefieras
    """
    Clase principal de la aplicación Kivy para el Análisis de Vulnerabilidades.
    """
    def build(self):
        """
        Este método construye la interfaz de usuario de la aplicación.
        Aquí también establecemos el icono de la aplicación.
        """
        # --- Configuración del icono de la aplicación ---
        # Asegúrate de que 'Icono1.png' esté en el mismo directorio que tu script principal
        self.icon = 'Icono1.png'
        # --------------------------------------------------

        # Crear un ScreenManager para manejar las diferentes pantallas
        screen_manager = ScreenManager()

        # Añadir la DashboardScreen al ScreenManager.
        # El 'name' es un identificador para esta pantalla.
        screen_manager.add_widget(DashboardScreen(name='dashboard_principal'))

        return screen_manager

# 4. Punto de entrada para ejecutar la aplicación
if __name__ == '__main__':
    # Instanciar y correr la aplicación
    AnalisisVulnerabilidadesApp().run()