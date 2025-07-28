# -*- coding: utf-8 -*-
import nmap
import threading
from kivy.clock import Clock
from kivy.uix.screenmanager import Screen
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.progressbar import ProgressBar
from kivy.lang import Builder
from kivy.properties import StringProperty, NumericProperty, BooleanProperty
from kivy.garden.graph import Graph, MeshLinePlot
import ipaddress
from collections import defaultdict
import time
from kivy.metrics import dp
from kivy.graphics import Rectangle, Color
import os # Para manejar rutas de archivos
from pathlib import Path # Importar Path para manejar rutas de manera más robusta
import socket # Para la detección automática de IP

# Importaciones para Scikit-learn y Pandas
import joblib # Para cargar los modelos .pkl
import pandas as pd # Para manejar las características como DataFrame

# Importaciones para la generación de PDF
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


Builder.load_file("gui/layout.kv")

SPANISH_SEVERITY = {
    "Critical": "Crítica", "High": "Alta", "Medium": "Media",
    "Low": "Baja", "Info": "Informativa", "Error": "Error"
}
UNIR_TEXT_DARK_PY = (0.1, 0.1, 0.1, 1)

# --- INICIO DE MUESTRAS DE MAPEOS Y LISTA DE CARACTERÍSTICAS (A SER COPIADAS DE train_ml_model.py) ---
# Copie y pegue aquí la salida exacta de su script train_ml_model.py
# Los valores exactos y el orden dependen de cómo entrenó sus modelos.

NUMERIC_TO_SPANISH_SEVERITY = {
    0: "Critical",
    1: "High",
    2: "Medium",
    3: "Low",
    4: "Info",
    # ¡IMPORTANTE! Reemplace estos valores con los que obtenga de la salida de train_ml_model.py
    # Ejemplo de un mapeo real podría ser:
    # 0: "Baja", 1: "Critica", 2: "Alta", 3: "Informativa", 4: "Media"
    # El orden y los nombres de las clases dependen de su LabelEncoder.
}

TREATMENT_SOLUTION_MAP = {
    0: "Actualizar vsftpd a la última versión para parchear vulnerabilidad.",
    1: "Configurar SSH para usar cifrados fuertes y deshabilitar los débiles.",
    2: "Deshabilitar Telnet y usar SSH para acceso remoto seguro.",
    3: "Revisar la configuración del servidor Apache y aplicar hardening.",
    # ¡IMPORTANTE! Reemplace estos valores con los que obtenga de la salida de train_ml_model.py
    # Asegúrese de que todos sus tratamientos estén mapeados aquí.
}

MASTER_FEATURES_LIST = [
    'port_number', 'is_common_web_port', 'is_common_db_port',
    'is_common_ssh_port', 'is_common_ftp_port', 'is_common_telnet_port',
    'service_apache', 'service_openssh', 'service_microsoft_iis',
    'service_ftp', 'service_telnet', 'service_mysql',
    'is_openssh_old', 'is_apache_2_2', 'is_telnet_open_unencrypted',
    'vulners_critical_found', 'vulners_high_found', 'vulners_medium_found', 'vulners_low_found',
    'vulners_script_output_present', 'port_state_open'
    # ¡IMPORTANTE! Reemplace esta lista con la que obtenga EXACTAMENTE de la salida de train_ml_model.py
    # El orden es CRÍTICO para la predicción del modelo.
]
# --- FIN DE MUESTRAS DE MAPEOS Y LISTA DE CARACTERÍSTICAS ---


class HostDataGroup(BoxLayout):
    """
    Custom widget to display scan results for a single host,
    including its detected vulnerabilities and services.
    Allows expanding and collapsing information.
    """
    def __init__(self, host_ip, vulnerabilities_for_host, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        # Binds the widget's height to the minimum height of its children for scrolling
        self.bind(minimum_height=self.setter('height'))
        self.spacing = dp(3)
        self.padding = [dp(5), dp(8), dp(5), dp(8)] # Internal spacing for better visualization

        # Host header with its IP and toggle button
        ip_header_layout = BoxLayout(size_hint_y=None, height=dp(45), spacing=dp(10), padding=[dp(5),0,dp(5),0])
        with ip_header_layout.canvas.before:
            Color(0.90, 0.92, 0.98, 1) # Background color for the header (light blue)
            self.header_bg_rect = Rectangle(size=ip_header_layout.size, pos=ip_header_layout.pos)
        ip_header_layout.bind(pos=self._update_header_rect, size=self._update_header_rect)

        ip_label = Label(text=f"Equipo: {host_ip}", bold=True, font_size='16sp', color=UNIR_TEXT_DARK_PY,
                         size_hint_x=0.8, halign='left', valign='middle')
        ip_label.bind(width=lambda instance, value: setattr(instance, 'text_size', (value, None)))
        ip_header_layout.add_widget(ip_label)

        self.toggle_btn = Button(text='-', size_hint_x=0.2, size_hint_y=None, height=dp(40),
                                 background_normal='', background_color=(0.7, 0.7, 0.8, 0.5)) # Toggle button with a neutral color
        self.toggle_btn.bind(on_press=self.toggle_content)
        ip_header_layout.add_widget(self.toggle_btn)
        self.add_widget(ip_header_layout)

        # Contenedor para la información de vulnerabilidades
        self.content = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(2))
        self.content.bind(minimum_height=self.content.setter('height'))
        self.is_expanded = True # Initial state: expanded

        if not vulnerabilities_for_host:
            # Mensaje si no se encontraron vulnerabilidades para el host
            self.content.add_widget(Label(text="  (No se encontraron vulnerabilidades o información específica)",
                                           size_hint_y=None, height=dp(30), halign='left',
                                           text_size=(self.width*0.95 if self.width > 0 else dp(200), None),
                                           color=(0.4,0.4,0.4,1)))
        else:
            # Cabecera de la tabla de vulnerabilidades
            vuln_table_header = BoxLayout(size_hint_y=None, height=dp(30), spacing=dp(2), padding=[dp(10),0,dp(5),0])
            vuln_table_header.add_widget(Label(text="Puerto", size_hint_x=0.10, bold=True, color=UNIR_TEXT_DARK_PY, font_size='13sp', halign='center', valign='middle'))
            service_header_label = Label(text="Servicio", size_hint_x=0.20, bold=True, color=UNIR_TEXT_DARK_PY, font_size='13sp', halign='left', valign='middle')
            service_header_label.bind(width=lambda instance, value: setattr(instance, 'text_size', (value, None)))
            vuln_table_header.add_widget(service_header_label)

            desc_header_label = Label(text="Descripción", size_hint_x=0.50, bold=True, color=UNIR_TEXT_DARK_PY, font_size='13sp', halign='left', valign='middle')
            desc_header_label.bind(width=lambda instance, value: setattr(instance, 'text_size', (value, None)))
            vuln_table_header.add_widget(desc_header_label)

            vuln_table_header.add_widget(Label(text="Severidad", size_hint_x=0.20, bold=True, color=UNIR_TEXT_DARK_PY, font_size='13sp', halign='center', valign='middle'))
            self.content.add_widget(vuln_table_header)

            # Orden de severidades para la visualización
            severity_order_map = {key: i for i, key in enumerate(['Critical', 'High', 'Medium', 'Low', 'Info', 'Error'])}
            sorted_vulnerabilities = sorted(
                vulnerabilities_for_host,
                key=lambda x: severity_order_map.get(x['severity'], 99) # Usa 99 para errores/desconocidos al final
            )

            # Añade cada vulnerabilidad como una fila en la tabla
            for vuln in sorted_vulnerabilities:
                row = BoxLayout(size_hint_y=None, spacing=dp(2), padding=[dp(10),dp(5),dp(5),dp(5)])
                row.bind(minimum_height=row.setter('height'))

                row.add_widget(Label(text=str(vuln['port']), size_hint_x=0.10, color=UNIR_TEXT_DARK_PY, font_size='12sp', halign='center', valign='middle'))

                service_label_data = Label(text=vuln['service'], size_hint_x=0.20, color=UNIR_TEXT_DARK_PY, font_size='12sp', halign='left', valign='top')
                service_label_data.bind(width=lambda instance, value: setattr(instance, 'text_size', (value, None)))
                row.add_widget(service_label_data)

                vuln_desc_label_data = Label(text=vuln['vulnerability'], size_hint_x=0.50, color=UNIR_TEXT_DARK_PY, font_size='12sp', halign='left', valign='top')
                vuln_desc_label_data.bind(width=lambda instance, value: setattr(instance, 'text_size', (instance.width, None)))
                row.add_widget(vuln_desc_label_data)

                severity_key = vuln['severity']
                severity_display_text = SPANISH_SEVERITY.get(severity_key, severity_key)
                s_color = (0.2,0.2,0.2,1) # Color por defecto
                if severity_key == 'Critical': s_color = (1,0,0,1) # Rojo
                elif severity_key == 'High': s_color = (1,0.5,0,1) # Naranja
                elif severity_key == 'Medium': s_color = (1,1,0,1) # Amarillo (amarillo puro es (1,1,0,1))
                elif severity_key == 'Low': s_color = (0,0.6,0,1) # Verde oscuro
                elif severity_key == 'Info': s_color = (0.2,0.5,0.8,1) # Azul claro
                elif severity_key == 'Error': s_color = (0.5,0.5,0.5,1) # Gris

                row.add_widget(Label(text=severity_display_text, size_hint_x=0.20, color=s_color, bold=True, font_size='12sp', halign='center', valign='middle'))
                self.content.add_widget(row)

        self.add_widget(self.content)

    def _update_header_rect(self, instance, value):
        """Actualiza la posición y tamaño del rectángulo de fondo de la cabecera."""
        if hasattr(self, 'header_bg_rect'):
            self.header_bg_rect.pos = instance.pos
            self.header_bg_rect.size = instance.size

    def toggle_content(self, instance):
        """Expande o colapsa el contenido de las vulnerabilidades del host."""
        if self.is_expanded:
            self.content.height = 0
            self.content.opacity = 0
            self.toggle_btn.text = '+'
        else:
            self.content.height = self.content.minimum_height
            self.content.opacity = 1
            self.toggle_btn.text = '-'
        self.is_expanded = not self.is_expanded

class DashboardScreen(Screen):
    """
    Pantalla principal de la aplicación que gestiona la lógica de escaneo,
    actualizaciones de UI y visualización de resultados.
    """
    scan_progress = NumericProperty(0) # Progreso del escaneo (0-100)
    scan_status = StringProperty("")   # Mensaje de estado actual (ej: "Escaneando...", "Completado")
    current_host = StringProperty("")  # Host que se está escaneando actualmente
    scan_active = BooleanProperty(False) # Indica si un escaneo está en curso

    MAX_HOSTS_LIMIT = 4096 # Límite máximo de hosts para escanear en un solo rango

    def __init__(self, **kwargs):
        super(DashboardScreen, self).__init__(**kwargs)
        self.scan_results = [] # Almacena todos los resultados del escaneo
        self.nm = nmap.PortScanner() # Instancia del escáner Nmap
        self.scan_thread = None # Hilo para ejecutar el escaneo en segundo plano
        self.hosts_scanned = 0 # Contador de hosts ya escaneados
        self.total_hosts = 0 # Número total de hosts en el rango
        self.hosts_to_scan_list = [] # Lista de IPs a escanear
        self._update_progress_event = None # Evento para actualizar la UI
        # Eliminadas las referencias a _background_rect_instruction ya que la Image fue quitada del KV.
        # self.ids.results_container._background_rect_instruction = None

        # Lista ordenada de IDs de octetos para facilitar el salto de foco
        self.ip_octet_ids = [
            'ip_inicial_octet1', 'ip_inicial_octet2', 'ip_inicial_octet3', 'ip_inicial_octet4',
            'ip_final_octet1', 'ip_final_octet2', 'ip_final_octet3', 'ip_final_octet4'
        ]

        # Inicializar modelos ML
        self.severity_model = None
        self.treatment_model = None # Nuevo modelo para tratamientos
        # Cargar los modelos ML después de que la interfaz de usuario se haya construido
        Clock.schedule_once(self._load_ml_models)


    def on_enter(self, *args):
        """
        Se llama cuando la pantalla se hace visible.
        Aquí es seguro acceder a self.ids.
        """
        # Se asegura que la IP local se detecte solo una vez cuando la pantalla entra en foco
        if self.ids.ip_inicial_octet1.text == "": # Si los campos están vacíos, intenta detectar la IP
             self._detect_local_ip_and_set_range()

        # Programa la actualización de la UI
        # Asegúrate de que el evento no se programe múltiples veces si on_enter se llama más de una vez
        if self._update_progress_event is None:
            self._update_progress_event = Clock.schedule_interval(self.update_progress_ui_elements, 0.1)

        # Eliminada la llamada a show_results_background_image ya que el widget Image fue eliminado del KV.
        # if not self.scan_active and not self.scan_results:
        #     self.show_results_background_image()


    def _validate_octet_input(self, octet_id, text_input_instance):
        """
        Validates if an IP octet input is a valid integer between 0 and 255.
        Highlights the TextInput in red if invalid.
        """
        text = text_input_instance.text.strip()
        if not text: # Allow empty string (e.g., during initial input) but mark as valid for now
            text_input_instance.background_color = (1, 1, 1, 1) # Reset to white
            return True # Consider empty as temporarily valid, full validation happens on scan start

        try:
            value = int(text)
            if not (0 <= value <= 255):
                text_input_instance.background_color = (1, 0.8, 0.8, 1) # Light red for error
                return False
            else:
                text_input_instance.background_color = (1, 1, 1, 1) # Reset to white
                return True
        except ValueError:
            text_input_instance.background_color = (1, 0.8, 0.8, 1) # Light red for error
            return False

    def _handle_octet_input(self, octet_id, instance, text):
        """
        Handles input in IP octet fields, specifically for '.' to jump focus.
        Also ensures that if max_length is reached, it. tries to jump focus.
        """
        # If a period is entered, or if the field has 3 characters and is a valid number,
        # try to move focus to the next octet.
        if (text.endswith('.') and len(text) > 0) or \
           (len(text) == 3 and self._validate_octet_input(octet_id, instance) and text.isdigit()):

            # If it ends with a period, remove it
            if text.endswith('.'):
                instance.text = text[:-1]

            current_id = octet_id # Use octet_id directly
            try:
                current_index = self.ip_octet_ids.index(current_id)
                next_index = current_index + 1
                if next_index < len(self.ip_octet_ids):
                    next_octet_id = self.ip_octet_ids[next_index]
                    self.ids[next_octet_id].focus = True
                else:
                    # If it's the last octet, remove focus or do something else
                    instance.focus = False
            except ValueError:
                # This should not occur if ip_octet_ids is well defined
                pass


    def _detect_local_ip_and_set_range(self):
        """
        Detects the local machine's IP address and populates the IP range fields.
        If detection fails, leaves the fields blank.
        """
        try:
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)) # Connect to an external host to get the local IP
            local_ip = s.getsockname()[0]
            s.close()

            # Parse the IP into octets
            ip_octets = local_ip.split('.')

            # Set initial IP fields
            self.ids.ip_inicial_octet1.text = ip_octets[0]
            self.ids.ip_inicial_octet2.text = ip_octets[1]
            self.ids.ip_inicial_octet3.text = ip_octets[2]
            self.ids.ip_inicial_octet4.text = "1" # Default start of range

            # Set final IP fields
            self.ids.ip_final_octet1.text = ip_octets[0]
            self.ids.ip_final_octet2.text = ip_octets[1]
            self.ids.ip_final_octet3.text = ip_octets[2]
            self.ids.ip_final_octet4.text = "254" # Default end of range

            # Color para el mensaje de IP local detectada
            self.ids.status_label.text = f"[color=0000FF]IP local detectada: {local_ip}. Rango pre-llenado.[/color]"

        except Exception as e:
            # If IP detection fails, leave the fields blank
            self.ids.ip_inicial_octet1.text = ""
            self.ids.ip_inicial_octet2.text = ""
            self.ids.ip_inicial_octet3.text = ""
            self.ids.ip_inicial_octet4.text = ""
            self.ids.ip_final_octet1.text = ""
            self.ids.ip_final_octet2.text = ""
            self.ids.ip_final_octet3.text = ""
            self.ids.ip_final_octet4.text = ""
            self.ids.status_label.text = f"[color=ffA500]No se pudo detectar la IP local. Ingrese el rango manualmente.[/color]"
            print(f"Error al detectar IP local: {e}")

    def _load_ml_models(self, dt):
        """
        Carga los modelos de Machine Learning (severidad y tratamientos)
        desde los archivos .pkl guardados.
        """
        try:
            # Asumiendo que los archivos .pkl están en el mismo directorio que main.py
            self.severity_model = joblib.load('severity_model.pkl')
            self.treatment_model = joblib.load('treatment_model.pkl')
            print("Modelos de ML cargados exitosamente.")
            self.ids.status_label.text = "[color=0000FF]Modelos de IA cargados. Listo para escanear.[/color]"
        except FileNotFoundError:
            self.ids.status_label.text = "[color=ffA500]Advertencia: Archivos de modelo ML no encontrados (severity_model.pkl o treatment_model.pkl). La clasificación y tratamientos de IA no funcionarán. Entrene los modelos primero ejecutando 'python train_ml_model.py'.[/color]"
            print("Advertencia: Archivos de modelo ML no encontrados. La clasificación y tratamientos de IA no funcionarán.")
            self.severity_model = None
            self.treatment_model = None
        except Exception as e:
            self.ids.status_label.text = f"[color=ff0000]Error al cargar modelos ML: {e}. La clasificación y tratamientos de IA podrían no funcionar.[/color]"
            print(f"Error al cargar modelos ML: {e}")
            self.severity_model = None
            self.treatment_model = None


    def validar_y_analizar(self):
        """
        Valida el rango de IP ingresado por el usuario y comienza el proceso de escaneo.
        Maneja la activación/desactivación del botón de escaneo y mensajes de estado.
        """
        if self.scan_active:
            # Si el escaneo está activo y se presiona el botón, se asume que es para detenerlo
            self.cancel_scan()
            return

        # Validate each octet before proceeding
        octet_ids_initial = ['ip_inicial_octet1', 'ip_inicial_octet2', 'ip_inicial_octet3', 'ip_inicial_octet4']
        octet_ids_final = ['ip_final_octet1', 'ip_final_octet2', 'ip_final_octet3', 'ip_final_octet4']

        all_octets_valid = True
        # Perform validation and update background color for all octets
        for octet_id in octet_ids_initial + octet_ids_final:
            # Pass the actual TextInput instance to the validation method
            if not self._validate_octet_input(octet_id, self.ids[octet_id]):
                all_octets_valid = False

        if not all_octets_valid:
            self.ids.status_label.text = "[color=ff0000]Error: Uno o más octetos de IP son inválidos (0-255).[/color]"
            return

        # Ensure no octet is empty before constructing the IP string for final validation
        for octet_id in octet_ids_initial + octet_ids_final:
            if not self.ids[octet_id].text.strip():
                self.ids.status_label.text = "[color=ff0000]Error: Todos los octetos de IP deben estar llenos.[/color]"
                self.ids[octet_id].background_color = (1, 0.8, 0.8, 1) # Highlight empty field
                return


        # Construct full IP strings from octet fields
        ip_inicial_str = f"{self.ids.ip_inicial_octet1.text}.{self.ids.ip_inicial_octet2.text}.{self.ids.ip_inicial_octet3.text}.{self.ids.ip_inicial_octet4.text}"
        ip_final_str = f"{self.ids.ip_final_octet1.text}.{self.ids.ip_final_octet2.text}.{self.ids.ip_final_octet3.text}.{self.ids.ip_final_octet4.text}"

        try:
            ip_start_obj = ipaddress.IPv4Address(ip_inicial_str)
            ip_end_obj = ipaddress.IPv4Address(ip_final_str)
        except ValueError: # This catch is mostly for structural IP errors (e.g., empty fields after manual clear)
            self.ids.status_label.text = "[color=ff0000]La dirección IP inicial o final es inválida.[/color]"
            return

        if ip_end_obj < ip_start_obj:
            self.ids.status_label.text = "[color=ff0000]La IP final debe ser mayor o igual que la IP inicial.[/color]"
            return

        self.hosts_to_scan_list = []
        current_ip_obj = ip_start_obj
        while current_ip_obj <= ip_end_obj:
            self.hosts_to_scan_list.append(str(current_ip_obj))
            if current_ip_obj == ipaddress.IPv4Address('255.255.255.255'): # Avoid infinite loops with the last IP
                break
            current_ip_obj += 1

        self.total_hosts = len(self.hosts_to_scan_list)

        if self.total_hosts == 0:
            self.ids.status_label.text = "[color=ff0000]No hay equipos en el rango especificado.[/color]"
            return

        if self.total_hosts > self.MAX_HOSTS_LIMIT:
            self.ids.status_label.text = f"[color=ffA500]El rango es demasiado grande ({self.total_hosts} equipos). El límite es {self.MAX_HOSTS_LIMIT}.[/color]"
            return
        
        if self.severity_model is None or self.treatment_model is None: # Comprobar ambos modelos
            self.ids.status_label.text = "[color=ffA500]Advertencia: Los modelos de IA no están cargados. El escaneo continuará sin clasificación inteligente y tratamientos.[/color]"
            # Permite continuar el escaneo, pero con advertencia.
        else:
            self.ids.status_label.text = f"[color=00ff00]Preparando escaneo de {self.total_hosts} equipo(s)...[/color]"

        self.scan_active = True # Activates scan status
        self.scan_results = [] # Resets results
        self.scan_progress = 0
        self.scan_status = "Iniciando escaneo..."
        self.current_host = ""
        self.hosts_scanned = 0

        # Starts the scan in a separate thread to avoid blocking the UI
        self.scan_thread = threading.Thread(target=self.run_nmap_scan)
        self.scan_thread.daemon = True # Allows the thread to terminate if the app closes
        self.scan_thread.start()

    def update_progress_ui_elements(self, dt):
        """
        Updates the UI elements that show the scan progress.
        This method is called periodically by Kivy's Clock.
        """
        # CRITICAL FIX: Check if the IDs exist before accessing them.
        # This prevents the KeyError if the UI elements are not yet fully built
        # when this method is called for the first time.
        if not self or not hasattr(self, 'ids') or 'bottom_scan_progressbar' not in self.ids or 'bottom_status_text' not in self.ids or 'bottom_current_host_label' not in self.ids:
            # If IDs are not ready, do nothing and continue scheduling until they are.
            return True

        if not self.scan_active: # If the scan is no longer active, stops updates
            if self._update_progress_event:
                self._update_progress_event.cancel()
                self._update_progress_event = None
            return False # Returns False to cancel the scheduling

        # Update progress bar and status labels
        self.ids.bottom_scan_progressbar.value = self.scan_progress
        self.ids.bottom_status_text.text = self.scan_status
        self.ids.bottom_current_host_label.text = ("Escaneando: " + self.current_host) if self.current_host else ""
        return True # Returns True to continue scheduling

    def run_nmap_scan(self):
        """
        Ejecuta el escaneo Nmap en un hilo separado.
        Itera sobre la lista de hosts y procesa los resultados.
        """
        # Construye los argumentos de Nmap basados en las selecciones del usuario
        args_list = []
        if self.ids.nmap_opt_sS.active: args_list.append('-sS')
        if self.ids.nmap_opt_sT.active: args_list.append('-sT')
        if self.ids.nmap_opt_sU.active: args_list.append('-sU')
        if self.ids.nmap_opt_O.active: args_list.append('-O')
        if self.ids.nmap_opt_sV.active: args_list.append('-sV')
        if self.ids.nmap_opt_Pn.active: args_list.append('-Pn') # No hacer ping, para hosts que no responden al ping
        if self.ids.nmap_opt_vulners.active: args_list.append('--script vulners') # Script de vulnerabilidades

        custom_args_str = self.ids.custom_nmap_args_input.text.strip()
        if custom_args_str:
            args_list.extend(custom_args_str.split())

        # Asegura que -sV se use si el script vulners está activo y no hay otro modo de escaneo de versión
        if '--script vulners' in args_list and '-sV' not in args_list and '-A' not in args_list:
            args_list.insert(0, '-sV')

        scan_args = ' '.join(args_list)

        if not self.hosts_to_scan_list: # Verifica que haya hosts para escanear
            Clock.schedule_once(lambda dt: self._set_scan_status("Error: No hay equipos para escanear."))
            Clock.schedule_once(self.finish_scan)
            return

        initial_status_msg = f"Escaneando rango: {self.hosts_to_scan_list[0]} - {self.hosts_to_scan_list[-1]} ({self.total_hosts} equipos)"
        if self.total_hosts == 1:
            initial_status_msg = f"Escaneando equipo: {self.hosts_to_scan_list[0]}"

        Clock.schedule_once(lambda dt: self._set_scan_status(initial_status_msg))

        try:
            for host_str in self.hosts_to_scan_list:
                if not self.scan_active:  # Permite cancelar el escaneo
                    break
                self.current_host = host_str # Actualiza el host actual para la UI
                current_scan_op_status = f"Escaneando {host_str} ({self.hosts_scanned + 1}/{self.total_hosts}). Args: {scan_args}"
                Clock.schedule_once(lambda dt, status=current_scan_op_status: self._set_scan_status(status))

                try:
                    self.nm.scan(hosts=host_str, arguments=scan_args)
                    self.process_nmap_results(host_str) # Procesa los resultados del host
                except Exception as e:
                    error_msg = f"Error escaneando {host_str}: {str(e)[:200]}" # Limita el mensaje de error
                    print(error_msg)
                    self.scan_results.append({
                        'ip': host_str, 'port': 'N/A', 'service': 'Error en escaneo',
                        'version': '', 'vulnerability': error_msg,
                        'severity': 'Error',
                        'recommendation': 'Fallo en escaneo Nmap.' # Añadir recomendación por defecto
                    })

                self.hosts_scanned += 1
                if self.total_hosts > 0:
                    self.scan_progress = (self.hosts_scanned / self.total_hosts) * 100
                else:
                    self.scan_progress = 0

            final_status_msg = "Escaneo completado" if self.scan_active else "Escaneo cancelado"
            Clock.schedule_once(lambda dt: self._set_scan_status(final_status_msg))

        except Exception as e: # Captura cualquier error general del hilo de escaneo
            error_final_msg = f"Error general durante el escaneo: {str(e)[:200]}"
            print(error_final_msg)
            Clock.schedule_once(lambda dt: self._set_scan_status(error_final_msg))
        finally:
            Clock.schedule_once(self.finish_scan) # Asegura que finish_scan se llame al final

    def _set_scan_status(self, status_text):
        """Auxiliary method to update the scan status in the main thread."""
        self.scan_status = status_text

    def _extract_features_for_ml(self, port_data, host_ip=None):
        """
        Extrae y prepara las características de los datos de un puerto Nmap
        para ser usadas por los modelos de Machine Learning.
        ¡CRÍTICO! Las características deben coincidir en nombre y ORDEN
        con las definidas en MASTER_FEATURES_LIST y usadas en el entrenamiento.
        """
        features_dict = {}

        # Extracción segura de datos con valores por defecto
        port = int(port_data.get('portid', 0))
        service_name = str(port_data.get('name', '')).lower()
        product = str(port_data.get('product', '')).lower()
        version = str(port_data.get('version', '')).lower()
        # Asegurarse de que vulners_output sea una cadena, incluso si no existe
        vulners_output = str(port_data.get('script', {}).get('vulners', '')).lower()

        # 1. Características numéricas/categóricas directas
        features_dict['port_number'] = port
        features_dict['is_common_web_port'] = 1 if port in [80, 443, 8080] else 0
        features_dict['is_common_db_port'] = 1 if port in [3306, 5432, 1433] else 0
        features_dict['is_common_ssh_port'] = 1 if port == 22 else 0
        features_dict['is_common_ftp_port'] = 1 if port == 21 else 0
        features_dict['is_common_telnet_port'] = 1 if port == 23 else 0

        # 2. Características de One-Hot Encoding para servicios (replicar de train_ml_model.py)
        features_dict['service_apache'] = 1 if 'apache' in product or 'httpd' in service_name else 0
        features_dict['service_openssh'] = 1 if 'openssh' in product or 'ssh' in service_name else 0
        features_dict['service_microsoft_iis'] = 1 if 'iis' in product else 0
        features_dict['service_ftp'] = 1 if 'ftp' in service_name else 0
        features_dict['service_telnet'] = 1 if 'telnet' in service_name else 0
        features_dict['service_mysql'] = 1 if 'mysql' in service_name else 0
        # ... (añada aquí todas las características 'service_X' que haya usado en su entrenamiento)

        # 3. Características basadas en versiones y configuraciones específicas
        is_openssh_old = 0
        if 'openssh' in product:
            if any(v_prefix in version for v_prefix in ['5.','6.']) or \
               ('7.' in version and 'p1' not in version and 'p2' not in version):
                is_openssh_old = 1
        features_dict['is_openssh_old'] = is_openssh_old
        features_dict['is_apache_2_2'] = 1 if 'apache' in product and '2.2' in version else 0
        features_dict['is_telnet_open_unencrypted'] = 1 if 'telnet' in service_name and port_data.get('state') == 'open' and 'ssl' not in port_data.get('extrainfo', '').lower() else 0

        # 4. Características derivadas de la salida del script Vulners
        features_dict['vulners_critical_found'] = 1 if 'critical' in vulners_output else 0
        features_dict['vulners_high_found'] = 1 if 'high' in vulners_output else 0
        features_dict['vulners_medium_found'] = 1 if 'medium' in vulners_output else 0
        features_dict['vulners_low_found'] = 1 if 'low' in vulners_output else 0
        features_dict['vulners_script_output_present'] = 1 if vulners_output else 0

        # 5. Estado del puerto
        features_dict['port_state_open'] = 1 if port_data.get('state') == 'open' else 0

        # Convertir el diccionario de características a un DataFrame de pandas
        try:
            # Crear un DataFrame con las características extraídas para una sola fila
            feature_vector = pd.DataFrame([features_dict])

            # Asegurarse de que el DataFrame tenga las mismas columnas y en el mismo orden
            # que la MASTER_FEATURES_LIST usada en el entrenamiento.
            # Rellenar columnas faltantes con 0
            missing_cols = set(MASTER_FEATURES_LIST) - set(feature_vector.columns)
            for c in missing_cols:
                feature_vector[c] = 0

            # Reordenar las columnas del DataFrame para que coincidan con la lista maestra
            feature_vector = feature_vector[MASTER_FEATURES_LIST]

            return feature_vector

        except Exception as e:
            print(f"Error al construir DataFrame de características para ML: {e}")
            return None

    def process_nmap_results(self, host):
        """
        Procesa los resultados del escaneo Nmap para un host dado,
        extrayendo servicios y utilizando los modelos ML para clasificar
        vulnerabilidades, interpretarlas y generar tratamientos.
        """
        if host not in self.nm.all_hosts():
            return

        host_data = self.nm[host]
        found_data_for_host = False

        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()

            for port in ports:
                port_data = host_data[proto][port]
                service_name = port_data.get('name', 'desconocido')
                product_version = port_data.get('product', '') + ' ' + port_data.get('version', '')

                predicted_severity = 'Info' # Valor por defecto
                interpreted_vulnerability = f"Servicio {service_name} activo en puerto {port}." # Interpretación por defecto
                proposed_treatment_solution = 'No se encontró tratamiento específico o se requiere revisión manual.' # Tratamiento por defecto

                # 1. Preparar las características para la predicción ML
                features_for_prediction = self._extract_features_for_ml(port_data, host)

                # 2. Realizar predicciones con los modelos ML
                # Solo intentar predecir si ambos modelos están cargados
                if features_for_prediction is not None and self.severity_model and self.treatment_model:
                    try:
                        # Predicción de severidad
                        predicted_severity_numeric = self.severity_model.predict(features_for_prediction)[0]
                        predicted_severity = NUMERIC_TO_SPANISH_SEVERITY.get(predicted_severity_numeric, "Unknown")

                        # Predicción de Tratamiento/Solución (la IA "interpreta" y propone)
                        predicted_treatment_id = self.treatment_model.predict(features_for_prediction)[0]
                        proposed_treatment_solution = TREATMENT_SOLUTION_MAP.get(predicted_treatment_id, proposed_treatment_solution)

                        # Construcción de la interpretación de la vulnerabilidad por la IA
                        # La IA "interpreta" combinando la info de Nmap con lo aprendido en el dataset
                        # Idealmente, esta interpretación podría venir de otro modelo de ML o una base de conocimiento
                        # Por ahora, la construimos combinando datos crudos y la salida de Vulners, como base para la "interpretación"
                        interpreted_vulnerability = f"Vulnerabilidad detectada en {service_name} ({product_version}) en el puerto {port}."
                        if 'vulners' in port_data.get('script', {}):
                            vuln_output = port_data['script']['vulners'].strip()
                            interpreted_vulnerability += f" Detalles del script Vulners: {vuln_output[:150]}..." if len(vuln_output) > 150 else f" Detalles del script Vulners: {vuln_output}"
                        elif port_data.get('extrainfo'):
                            interpreted_vulnerability += f" Información adicional: {port_data['extrainfo'][:100]}..." if len(port_data['extrainfo']) > 100 else f" Información adicional: {port_data['extrainfo']}"
                        
                        # Limitar longitud total de la interpretación
                        interpreted_vulnerability = interpreted_vulnerability[:250]

                        # Añadir el resultado con las predicciones del ML
                        self.scan_results.append({
                            'ip': host, 'port': str(port),
                            'service': service_name, 'version': product_version,
                            'vulnerability': interpreted_vulnerability, # Ahora es la interpretación de la IA
                            'severity': predicted_severity,
                            'recommendation': proposed_treatment_solution # Ahora es el tratamiento propuesto por la IA
                        })
                        found_data_for_host = True

                    except Exception as e:
                        print(f"Error en la predicción ML (severidad/tratamiento) para {host}:{port}: {e}")
                        self.scan_results.append({
                            'ip': host, 'port': str(port),
                            'service': service_name, 'version': product_version,
                            'vulnerability': f"Error en análisis ML: {str(e)[:150]}",
                            'severity': 'Error',
                            'recommendation': 'Revisión manual necesaria debido a error ML en clasificación/tratamiento.'
                        })
                        found_data_for_host = True

                elif port_data.get('state') == 'open':
                    # Lógica de fallback si los modelos ML no están cargados o no aplicables
                    self.scan_results.append({
                        'ip': host, 'port': str(port),
                        'service': service_name, 'version': product_version,
                        'vulnerability': f"Servicio {service_name} activo. Sin interpretación de IA.",
                        'severity': 'Info',
                        'recommendation': 'Verificar necesidad del servicio y configuraciones seguras manualmente.'
                    })
                    found_data_for_host = True

        # Lógica para hosts que responden al ping pero sin puertos abiertos o sin ML
        if not found_data_for_host and host in self.nm.all_hosts() and self.nm[host].state() == 'up':
            os_name = ''
            if self.nm[host].get('osmatch'):
                if self.nm[host]['osmatch']:
                    os_name = self.nm[host]['osmatch'][0].get('name', '')
            self.scan_results.append({
                'ip': host, 'port': '-', 'service': 'Equipo Activo',
                'version': os_name,
                'vulnerability': 'El equipo respondió al escaneo. No se detectó información detallada de servicios o vulnerabilidades.',
                'severity': 'Info',
                'recommendation': 'Realizar escaneo más profundo o revisión manual para identificar servicios y vulnerabilidades.'
            })


    def finish_scan(self, dt=None):
        """
        Method called when the scan finishes or is cancelled.
        Updates the final status and displays the results.
        """
        self.scan_active = False
        # Cancels the progress update event if it's still scheduled
        if self._update_progress_event:
            self._update_progress_event.cancel()
            self._update_progress_event = None

        self.display_results() # Calls the function to display detailed results

        # Builds a summary message for the main status label
        summary_text_parts = []
        
        if self.scan_status == "Escaneo cancelado":
            summary_text_parts.append("[color=FFA500]Escaneo cancelado por el usuario.[/color]")
        elif "Error" in self.scan_status : # If the status contains "Error", assumes there was a problem
             summary_text_parts.append(f"[color=ff0000]{self.scan_status}[/color]")
        else: # Assumes completed if not cancelled or error
            summary_text_parts.append("[color=00ff00]Escaneo finalizado. [/color]")

        if self.scan_results:
            # Counts vulnerabilities by severity
            crit = len([r for r in self.scan_results if r['severity'] == 'Critical'])
            high = len([r for r in self.scan_results if r['severity'] == 'High'])
            med = len([r for r in self.scan_results if r['severity'] == 'Medium'])
            low = len([r for r in self.scan_results if r['severity'] == 'Low'])
            info = len([r for r in self.scan_results if r['severity'] == 'Info'])

            vuln_counts_display = []
            if crit > 0: vuln_counts_display.append(f"[color=ff0000]{crit} {SPANISH_SEVERITY['Critical']}s[/color]")
            if high > 0: vuln_counts_display.append(f"[color=ff6600]{high} {SPANISH_SEVERITY['High']}s[/color]")
            if med > 0: vuln_counts_display.append(f"[color=FFD700]{med} {SPANISH_SEVERITY['Medium']}s[/color]") # Color amarillo-oro
            if low > 0: vuln_counts_display.append(f"[color=008000]{low} {SPANISH_SEVERITY['Low']}s[/color]") # Verde oscuro
            if info > 0: vuln_counts_display.append(f"[color=4169E1]{info} {SPANISH_SEVERITY['Info']}s[/color]") # Azul real

            if vuln_counts_display:
                summary_text_parts.append("Resumen de Hallazgos: " + ", ".join(vuln_counts_display))
            elif self.scan_status not in ["Escaneo cancelado"] and "Error" not in self.scan_status :
                 summary_text_parts.append("No se encontraron vulnerabilidades significativas.")
        elif self.scan_status not in ["Escaneo cancelado"] and "Error" not in self.scan_status :
             summary_text_parts.append("No se encontraron equipos o hallazgos relevantes.")

        self.ids.status_label.text = " ".join(summary_text_parts)
        self.current_host = "" # Clears current host


    def display_results(self):
        """
        Displays scan results in the UI results container,
        grouped by host and with a general summary and chart.
        """
        results_container = self.ids.results_container
        results_container.clear_widgets() # Clears previous results

        if not self.scan_results:
            results_container.add_widget(Label(text="No se encontraron resultados para mostrar.",
                                            size_hint_y=None, height=dp(40)))
            return

        # Groups results by host IP address
        grouped_by_host = defaultdict(list)
        for result in self.scan_results:
            grouped_by_host[result['ip']].append(result)

        if not grouped_by_host:
             results_container.add_widget(Label(text="No hay datos de equipos para mostrar.",
                                            size_hint_y=None, height=dp(40)))
             self.add_summary_and_chart(results_container) # Ensures summary and chart are shown even if only 'up' hosts
             return

        # Sorts hosts by IP for consistent display
        sorted_host_ips = sorted(grouped_by_host.keys(), key=lambda ip: ipaddress.ip_address(ip))

        # Adds a HostDataGroup for each host
        for host_ip in sorted_host_ips:
            vulnerabilities_for_this_host = grouped_by_host[host_ip]
            host_group_widget = HostDataGroup(
                host_ip=host_ip,
                vulnerabilities_for_host=vulnerabilities_for_this_host
            )
            results_container.add_widget(host_group_widget)

        self.add_summary_and_chart(results_container) # Adds summary and chart at the end


    def add_summary_and_chart(self, container):
        """
        Adds a summary of vulnerabilities and a bar chart to the results container.
        """
        summary_box = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(5))
        summary_box.bind(minimum_height=summary_box.setter('height')) # Adjusts summary height

        summary_title = Label(text="Resumen General del Escaneo", bold=True, size_hint_y=None, height=dp(30), color=UNIR_TEXT_DARK_PY)
        summary_box.add_widget(summary_title)

        stats_layout = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(5))

        # Calculates vulnerability statistics
        unique_hosts_with_findings = len({r['ip'] for r in self.scan_results if r['severity'] != 'Error' and not (r['service'] == 'Equipo Activo' and r['vulnerability'].startswith('El equipo respondió'))})
        total_vulns = len([r for r in self.scan_results if r['severity'] not in ['Info', 'Error']])
        crit = len([r for r in self.scan_results if r['severity'] == 'Critical'])
        high = len([r for r in self.scan_results if r['severity'] == 'High'])
        med = len([r for r in self.scan_results if r['severity'] == 'Medium'])
        low = len([r for r in self.scan_results if r['severity'] == 'Low'])
        info_count = len([r for r in self.scan_results if r['severity'] == 'Info'])

        vuln_counts_display = []
        if crit > 0: vuln_counts_display.append(f"[color=ff0000]{crit} {SPANISH_SEVERITY['Critical']}s[/color]")
        if high > 0: vuln_counts_display.append(f"[color=ff6600]{high} {SPANISH_SEVERITY['High']}s[/color]")
        if med > 0: vuln_counts_display.append(f"[color=FFD700]{med} {SPANISH_SEVERITY['Medium']}s[/color]") # Color amarillo-oro
        if low > 0: vuln_counts_display.append(f"[color=008000]{low} {SPANISH_SEVERITY['Low']}s[/color]") # Verde oscuro
        if info_count > 0: vuln_counts_display.append(f"[color=4169E1]{info_count} {SPANISH_SEVERITY['Info']}s[/color]") # Azul real

        if vuln_counts_display:
            stats_layout.add_widget(Label(text="Resumen de Hallazgos: " + ", ".join(vuln_counts_display), color=UNIR_TEXT_DARK_PY, size_hint_y=None, height=dp(30)))
        else:
            stats_layout.add_widget(Label(text="No se encontraron vulnerabilidades significativas.", color=UNIR_TEXT_DARK_PY, size_hint_y=None, height=dp(30)))

        summary_box.add_widget(stats_layout)
        container.add_widget(summary_box)

        # Creates a bar chart if there are vulnerabilities or information
        if total_vulns > 0 or info_count > 0 :
            graph_box = BoxLayout(size_hint_y=None, height=dp(250), padding=dp(10))
            try:
                graph = Graph(
                    xlabel='Severidad', ylabel='Cantidad',
                    x_ticks_minor=0, x_ticks_major=1, # X-axis: 1 major tick per bar
                    y_ticks_major=1, y_grid_label=True, x_grid_label=True,
                    padding=dp(5), x_grid=True, y_grid=True,
                    xmin=-0.5, xmax=4.5, ymin=0, font_size='9sp',
                    background_color=(0.98, 0.98, 0.98, 1), # Graph background
                    border_color=(0.7,0.7,0.7,1),
                    label_options={'color': UNIR_TEXT_DARK_PY} # Graph label color
                )

                values_for_graph = [crit, high, med, low, info_count] # Values for bars
                max_y_val = max(values_for_graph) if values_for_graph else 0
                graph.y_ticks_major = max(1, int(max_y_val / 4)) if max_y_val > 0 else 1 # Adjusts Y-axis ticks dynamically

                # Colors for each bar (mejorados para visibilidad)
                plot_colors = {
                    'Critical': [1, 0, 0, 1],       # Rojo puro
                    'High': [1, 0.5, 0, 1],         # Naranja puro
                    'Medium': [1, 0.84, 0, 1],      # Amarillo-naranja (Goldenrod)
                    'Low': [0, 0.5, 0, 1],          # Verde oscuro
                    'Info': [0.25,0.41,0.88,1]      # Azul cornflower
                }
                # Labels for X-axis
                severity_graph_labels = [SPANISH_SEVERITY.get(s,s) for s in ['Critical', 'High', 'Medium', 'Low', 'Info']]

                bar_width = 0.5
                for i, severity_key_for_plot in enumerate(['Critical', 'High', 'Medium', 'Low', 'Info']):
                    # Para dibujar rectángulos (barras) en la gráfica
                    # Las barras se dibujan como polígonos cerrados
                    points = [
                        (i - bar_width / 2, 0),                       # Esquina inferior izquierda
                        (i - bar_width / 2, values_for_graph[i]),    # Esquina superior izquierda
                        (i + bar_width / 2, values_for_graph[i]),    # Esquina superior derecha
                        (i + bar_width / 2, 0),                       # Vuelve a la esquina inferior izquierda para cerrar el polígono
                    ]
                    
                    plot = MeshLinePlot(color=plot_colors[severity_key_for_plot])
                    plot.points = points
                    graph.add_plot(plot)


                graph.ymax = max(1, max_y_val + graph.y_ticks_major) # Ensures ymax is at least the max value + one tick
                graph.x_labels = {i: name for i, name in enumerate(severity_graph_labels)} # Assigns labels to X positions
                graph_box.add_widget(graph)
                container.add_widget(graph_box)
            except Exception as e:
                print(f"Error creating graph: {e}")
                container.add_widget(Label(text=f"Error al generar gráfico: {str(e)[:100]}", size_hint_y=None, height=dp(30), color=UNIR_TEXT_DARK_PY))

    def cancel_scan(self):
        """
        Stops the current scan if active.
        """
        if self.scan_active:
            self.scan_active = False # Changes state to stop the scan thread
            self.ids.status_label.text = "[color=FFA500]Cancelando escaneo, por favor espere...[/color]"
            print("Solicitud de cancelación de escaneo recibida.")

    def export_results_to_pdf(self):
        """
        Generates a PDF report with scan results.
        """
        if not self.scan_results:
            self.ids.status_label.text = "[color=ff0000]No hay resultados de escaneo para exportar.[/color]"
            return

        self._set_scan_status("Generando informe PDF...")
        # Runs in a thread to avoid blocking the UI
        threading.Thread(target=self._generate_pdf_report_thread).start()

    def _generate_pdf_report_thread(self):
        """
        Logic to generate the PDF report, executed in a separate thread.
        """
        try:
            # Define styles
            styles = getSampleStyleSheet()

            # Custom styles for the report
            title_style = styles['h1']
            title_style.alignment = 1 # Center
            title_style.textColor = colors.HexColor('#0069AA') # UNIR_BLUE

            h2_style = styles['h2']
            h2_style.textColor = colors.HexColor('#00558E') # UNIR_DARK_BLUE

            normal_style = styles['Normal']
            normal_style.fontSize = 10
            normal_style.leading = 12 # Line spacing

            small_text_style = ParagraphStyle(
                'smallText',
                parent=normal_style,
                fontSize=8,
                textColor=colors.grey,
                leading=10
            )

            # PDF file name
            filename = f"ScanIA_Informe_Vulnerabilidades_{time.strftime('%Y%m%d_%H%M%S')}.pdf"

            # By default, in this simulated environment, we only try the working directory:
            report_path = filename

            doc = SimpleDocTemplate(report_path, pagesize=letter)
            story = []

            # Report title
            story.append(Paragraph("Informe de Análisis de Vulnerabilidades - ScanIA", title_style))
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph(f"Fecha del Informe: {time.strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
            story.append(Spacer(1, 0.1 * inch))
            story.append(Paragraph(f"Rango de IPs Escaneado: {self.hosts_to_scan_list[0]} - {self.hosts_to_scan_list[-1]}", normal_style))
            story.append(Spacer(1, 0.3 * inch))

            # General Scan Summary
            story.append(Paragraph("Resumen General", h2_style))
            story.append(Spacer(1, 0.1 * inch))

            unique_hosts_with_findings = len({r['ip'] for r in self.scan_results if r['severity'] != 'Error' and not (r['service'] == 'Equipo Activo' and r['vulnerability'].startswith('El equipo respondió'))})
            total_vulns = len([r for r in self.scan_results if r['severity'] not in ['Info', 'Error']])
            crit = len([r for r in self.scan_results if r['severity'] == 'Critical'])
            high = len([r for r in self.scan_results if r['severity'] == 'High'])
            med = len([r for r in self.scan_results if r['severity'] == 'Medium'])
            low = len([r for r in self.scan_results if r['severity'] == 'Low'])
            info = len([r for r in self.scan_results if r['severity'] == 'Info'])

            summary_data = [
                ['Métrica', 'Cantidad'],
                ['Total de Equipos Escaneados', str(self.total_hosts)],
                ['Equipos con Hallazgos Relevantes', str(unique_hosts_with_findings)],
                ['Vulnerabilidades Detectadas (sin Info/Errores)', str(total_vulns)],
                [f"Severidad: {SPANISH_SEVERITY['Critical']}", str(crit)],
                [f"Severidad: {SPANISH_SEVERITY['High']}", str(high)],
                [f"Severidad: {SPANISH_SEVERITY['Medium']}", str(med)],
                [f"Severidad: {SPANISH_SEVERITY['Low']}", str(low)],
                [f"Severidad: {SPANISH_SEVERITY['Info']}", str(info)]
            ]

            table_style = TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0069AA')), # Encabezado azul
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (0,-1), 'LEFT'), # Left align first column
                ('ALIGN', (1,0), (-1,-1), 'RIGHT'), # Right align second column onwards
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 12),
                ('BACKGROUND', (0,1), (-1,-1), colors.beige),
                ('GRID', (0,0), (-1,-1), 1, colors.grey),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('FONTSIZE', (0,0), (-1,-1), 9), # Font size for the table
            ])

            # Color summary table rows by severity
            for i, row_data in enumerate(summary_data):
                if i == 0: continue # Skip header
                if f"Severidad: {SPANISH_SEVERITY['Critical']}" in row_data[0]:
                    table_style.add('TEXTCOLOR', (0, i), (-1, i), colors.red)
                elif f"Severidad: {SPANISH_SEVERITY['High']}" in row_data[0]:
                    table_style.add('TEXTCOLOR', (0, i), (-1, i), colors.darkorange)
                elif f"Severidad: {SPANISH_SEVERITY['Medium']}" in row_data[0]:
                    table_style.add('TEXTCOLOR', (0, i), (-1, i), colors.darkgoldenrod) # Dark yellow for visibility on white
                elif f"Severidad: {SPANISH_SEVERITY['Low']}" in row_data[0]:
                    table_style.add('TEXTCOLOR', (0, i), (-1, i), colors.darkgreen)
                elif f"Severidad: {SPANISH_SEVERITY['Info']}" in row_data[0]:
                    table_style.add('TEXTCOLOR', (0, i), (-1, i), colors.blue)

            table = Table(summary_data)
            table.setStyle(table_style)
            story.append(table)
            story.append(Spacer(1, 0.3 * inch))

            # Host Details
            story.append(Paragraph("Detalles de Hallazgos por Equipo", h2_style))
            story.append(Spacer(1, 0.1 * inch))

            grouped_by_host = defaultdict(list)
            for result in self.scan_results:
                grouped_by_host[result['ip']].append(result)

            sorted_host_ips = sorted(grouped_by_host.keys(), key=lambda ip: ipaddress.ip_address(ip))

            if not grouped_by_host:
                story.append(Paragraph("No se encontraron hallazgos detallados para mostrar en el informe.", normal_style))
            else:
                for host_ip in sorted_host_ips:
                    story.append(Paragraph(f"<b>Equipo: {host_ip}</b>", normal_style))
                    story.append(Spacer(1, 0.05 * inch))

                    vulnerabilities_for_this_host = grouped_by_host[host_ip]

                    # Data for host vulnerabilities table
                    host_vuln_data = [['Puerto', 'Servicio', 'Versión', 'Vulnerabilidad', 'Severidad', 'Tratamiento Propuesto']] # Encabezado para la columna de tratamiento

                    severity_order_map = {key: i for i, key in enumerate(['Critical', 'High', 'Medium', 'Low', 'Info', 'Error'])}
                    sorted_vulnerabilities = sorted(
                        vulnerabilities_for_this_host,
                        key=lambda x: severity_order_map.get(x['severity'], 99)
                    )

                    for vuln in sorted_vulnerabilities:
                        severity_display_text = SPANISH_SEVERITY.get(vuln['severity'], vuln['severity'])
                        host_vuln_data.append([
                            vuln['port'], vuln['service'], vuln['version'],
                            vuln['vulnerability'], severity_display_text,
                            vuln.get('recommendation', 'N/A') # Ahora obtiene el tratamiento propuesto
                        ])

                    if len(host_vuln_data) > 1: # If more than just the header
                        host_table_style = TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
                            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                            ('BOTTOMPADDING', (0,0), (-1,0), 6),
                            ('BACKGROUND', (0,1), (-1,-1), colors.white),
                            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                            ('VALIGN', (0,0), (-1,-1), 'TOP'),
                            ('FONTSIZE', (0,0), (-1,-1), 8), # Font size for host table
                        ])

                        # Color severity column in host table
                        for i, row_data in enumerate(host_vuln_data):
                            if i == 0: continue # Skip header
                            severity_key = [k for k, v in SPANISH_SEVERITY.items() if v == row_data[-2]]
                            if severity_key and severity_key[0] == 'Critical':
                                host_table_style.add('TEXTCOLOR', (-2, i), (-2, i), colors.red)
                            elif severity_key and severity_key[0] == 'High':
                                host_table_style.add('TEXTCOLOR', (-2, i), (-2, i), colors.darkorange)
                            elif severity_key and severity_key[0] == 'Medium':
                                host_table_style.add('TEXTCOLOR', (-2, i), (-2, i), colors.darkgoldenrod)
                            elif severity_key and severity_key[0] == 'Low':
                                host_table_style.add('TEXTCOLOR', (-2, i), (-2, i), colors.darkgreen)
                            elif severity_key and severity_key[0] == 'Info':
                                host_table_style.add('TEXTCOLOR', (-2, i), (-2, i), colors.blue)

                        host_table = Table(host_vuln_data, colWidths=[0.6*inch, 1.0*inch, 1.0*inch, 2.0*inch, 0.8*inch, 1.8*inch]) # Ajustar el ancho de la última columna
                        host_table.setStyle(host_table_style)
                        story.append(host_table)
                        story.append(Spacer(1, 0.2 * inch))
                    else:
                        story.append(Paragraph("  No se encontraron vulnerabilidades específicas para este equipo, solo información general.", small_text_style))
                        story.append(Spacer(1, 0.1 * inch))

            doc.build(story) # Builds the PDF

            Clock.schedule_once(lambda dt: self._set_scan_status(f"[color=00ff00]Informe generado. El archivo '{filename}' se guardaría en el directorio de la aplicación si fuera un entorno local.[/color]"))
            print(f"Informe PDF generado en (teórica): {os.getcwd()}/{filename}") # Shows current working directory
        except ImportError:
            # Error handling if reportlab is not installed
            Clock.schedule_once(lambda dt: self._set_scan_status(
                "[color=ff0000]Error: La librería 'reportlab' no está instalada. Ejecute 'pip install reportlab'.[/color]"
            ))
            print("Error: reportlab no está instalado.")
        except (IOError, OSError) as e:
            # Specific handling for read/write errors (e.g., permissions)
            error_message = f"Error al guardar el informe PDF: Permiso denegado o ruta inválida. ({str(e)}). Si está en su equipo, intente guardar en una carpeta con permisos de escritura (ej: Documentos o Escritorio)."
            Clock.schedule_once(lambda dt: self._set_scan_status(f"[color=ff0000]{error_message}[/color]"))
            print(f"ERROR DE ESCRITURA: {error_message}")
        except Exception as e:
            # Other errors during PDF generation
            error_msg = f"Error inesperado al generar el informe PDF: {str(e)[:200]}"
            Clock.schedule_once(lambda dt: self._set_scan_status(f"[color=ff0000]{error_msg}[/color]"))
            print(error_msg)