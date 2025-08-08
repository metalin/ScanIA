# -*- coding: utf-8 -*-
import nmap
import threading
from kivy.clock import Clock
from kivy.uix.screenmanager import Screen
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar
from kivy.lang import Builder
from kivy.properties import StringProperty, NumericProperty, BooleanProperty, ListProperty, BoundedNumericProperty
from kivy.uix.image import Image
from kivy.uix.filechooser import FileChooserListView
import ipaddress
from collections import defaultdict
import time
from kivy.metrics import dp
from kivy.graphics import Rectangle, Color, RoundedRectangle, Line
import os
from pathlib import Path
import socket
from kivy.uix.widget import Widget

import joblib
import pandas as pd

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

Builder.load_file("gui/layout.kv")

Builder.load_string("""
<Bar>:
    canvas:
        Color:
            rgba: 0.9, 0.9, 0.9, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(5)]
        Color:
            rgba: self.color
        RoundedRectangle:
            pos: self.pos
            size: self.width, self.height * self.value
            radius: [dp(5)]
""")

SPANISH_SEVERITY = {
    "Critical": "Crítica", "High": "Alta", "Medium": "Media",
    "Low": "Baja", "Info": "Informativa", "Error": "Error"
}
COLOR_TEXT_DARK_PY = (0.1, 0.1, 0.1, 1)

# Se asume que los IDs numéricos corresponden a un mapeo. 
# Es crucial que estos mapas coincidan con los usados durante el entrenamiento.
NUMERIC_TO_SPANISH_SEVERITY = {
    4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"
}
TREATMENT_SOLUTION_MAP = {
    0: "Actualizar o restringir acceso por firewall.",
    1: "Revisar configuración del servicio.",
    2: "Monitorear el servicio regularmente.",
    3: "Aplicar recomendaciones de seguridad básicas.",
    4: "Aplicar parches de seguridad inmediatamente.",
    # Se mantienen las soluciones 6 y 7 por si acaso
    6: "Revisión manual requerida. La IA no tiene suficiente confianza en la predicción.",
    7: "Sistema CCTV detectado. Cambiar credenciales por defecto, actualizar firmware y aislar la red de cámaras si es posible."
}

MASTER_FEATURES_LIST = [
    'is_common_web_port', 'is_common_db_port', 'is_common_ssh_port',
    'is_common_ftp_port', 'is_common_telnet_port', 'service_apache', 'service_openssh',
    'service_microsoft_iis', 'service_ftp', 'service_telnet', 'service_mysql',
    'is_openssh_old', 'is_apache_2_2', 'is_telnet_open_unencrypted',
    'vulners_critical_found', 'vulners_high_found', 'vulners_medium_found',
    'vulners_low_found', 'vulners_script_output_present', 'port_state_open'
]

class Bar(Widget):
    value = BoundedNumericProperty(0, min=0, max=1)
    color = ListProperty([0.5, 0.5, 0.5, 1])

class SummaryChart(BoxLayout):
    def __init__(self, counts, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.size_hint_y = None
        self.height = dp(220)
        self.spacing = dp(15)

        severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        colors = {
            'Critical': [1, 0.2, 0.2, 1], 
            'High': [1, 0.5, 0.2, 1], 
            'Medium': [0.9, 0.7, 0, 1], 
            'Low': [0.2, 0.6, 0.2, 1], 
            'Info': [0.25, 0.41, 0.88, 1]
        }
        
        all_counts = [counts.get(s, 0) for s in severities]
        if not any(c > 0 for c in all_counts):
            self.height = 0
            return

        max_count = max(all_counts) or 1

        for severity in severities:
            count = counts.get(severity, 0)
            
            bar_container = BoxLayout(orientation='vertical', spacing=dp(5))
            bar_container.add_widget(Label(text=str(count), size_hint_y=None, height=dp(20), font_size='12sp', color=COLOR_TEXT_DARK_PY, bold=True))
            bar_widget = Bar(value=(count / max_count), color=colors[severity])
            bar_container.add_widget(bar_widget)
            bar_container.add_widget(Label(text=SPANISH_SEVERITY[severity], size_hint_y=None, height=dp(20), font_size='11sp', color=COLOR_TEXT_DARK_PY))
            self.add_widget(bar_container)

class HostDataGroup(BoxLayout):
    def __init__(self, host_ip, vulnerabilities_for_host, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.bind(minimum_height=self.setter('height'))
        self.spacing = dp(5)
        self.padding = [dp(1)]

        with self.canvas.before:
            Color(0.96, 0.97, 1, 1)
            self.bg_rect = RoundedRectangle(size=self.size, pos=self.pos, radius=[dp(12)])
            Color(0.8, 0.82, 0.9, 1)
            self.border = Line(rounded_rectangle=(self.x, self.y, self.width, self.height, dp(12)), width=1.1)
        self.bind(pos=self._update_graphics, size=self._update_graphics)

        ip_header_layout = BoxLayout(size_hint_y=None, height=dp(45), spacing=dp(10), padding=[dp(12), 0, dp(12), 0])
        ip_label = Label(text=f"Equipo: {host_ip}", bold=True, font_size='17sp', color=COLOR_TEXT_DARK_PY,
                         size_hint_x=0.8, halign='left', valign='middle')
        ip_label.bind(width=lambda instance, value: setattr(instance, 'text_size', (value, None)))
        ip_header_layout.add_widget(ip_label)

        self.toggle_btn = Button(text='-', size_hint_x=0.2, size_hint_y=None, height=dp(38),
                                 background_normal='', background_color=(0.85, 0.85, 0.9, 0.6))
        self.toggle_btn.bind(on_press=self.toggle_content)
        ip_header_layout.add_widget(self.toggle_btn)
        self.add_widget(ip_header_layout)
        
        separator = BoxLayout(size_hint_y=None, height=dp(1))
        with separator.canvas:
            Color(0.8, 0.82, 0.9, 1)
            Rectangle(pos=(self.x + dp(12), ip_header_layout.y), size=(self.width - dp(24), dp(1)))
        self.add_widget(separator)

        self.content = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(6), padding=[dp(12), dp(8)])
        self.content.bind(minimum_height=self.content.setter('height'))
        self.is_expanded = True

        if not vulnerabilities_for_host:
            self.content.add_widget(Label(text="(No se encontraron vulnerabilidades o información específica)",
                                           size_hint_y=None, height=dp(30), halign='left',
                                           color=(0.4, 0.4, 0.4, 1)))
        else:
            vuln_table_header = BoxLayout(size_hint_y=None, height=dp(35), spacing=dp(5))
            headers_info = [
                ("Puerto", 0.08), ("Servicio", 0.15), ("Descripción", 0.27),
                ("Severidad", 0.15), ("Tratamiento Propuesto", 0.35)
            ]
            for text, size_hint in headers_info:
                header_label = Label(text=text, size_hint_x=size_hint, bold=True, color=COLOR_TEXT_DARK_PY,
                                     font_size='13sp', halign='left', valign='middle')
                header_label.bind(width=lambda instance, value: setattr(instance, 'text_size', (value, None)))
                vuln_table_header.add_widget(header_label)
            self.content.add_widget(vuln_table_header)

            severity_order_map = {key: i for i, key in enumerate(['Critical', 'High', 'Medium', 'Low', 'Info', 'Error'])}
            sorted_vulnerabilities = sorted(
                vulnerabilities_for_host, key=lambda x: severity_order_map.get(x['severity'], 99)
            )

            for vuln in sorted_vulnerabilities:
                row = BoxLayout(size_hint_y=None, spacing=dp(5))
                row.bind(minimum_height=row.setter('height'))
                
                def create_wrapping_label(text, size_hint_x, color=COLOR_TEXT_DARK_PY, bold=False):
                    label = Label(text=text, size_hint_x=size_hint_x, size_hint_y=None, color=color, bold=bold,
                                  font_size='12sp', halign='left', valign='top')
                    label.bind(width=lambda instance, value: setattr(instance, 'text_size', (value, None)))
                    label.bind(texture_size=lambda instance, value: setattr(instance, 'height', value[1]))
                    return label

                row.add_widget(create_wrapping_label(str(vuln['port']), 0.08))
                row.add_widget(create_wrapping_label(vuln['service'], 0.15))
                row.add_widget(create_wrapping_label(vuln['vulnerability'], 0.27))
                
                severity_key = vuln['severity']
                severity_display_text = SPANISH_SEVERITY.get(severity_key, severity_key)
                s_color = {'Critical': (1,0,0,1), 'High': (1,0.5,0,1), 'Medium': (0.9,0.7,0,1),
                           'Low': (0,0.6,0,1), 'Info': (0.2,0.5,0.8,1), 'Error': (0.5,0.5,0.5,1)
                          }.get(severity_key, (0.2,0.2,0.2,1))
                row.add_widget(create_wrapping_label(severity_display_text, 0.15, color=s_color, bold=True))
                
                row.add_widget(create_wrapping_label(vuln.get('recommendation', 'N/A'), 0.35))
                self.content.add_widget(row)

        self.add_widget(self.content)

    def _update_graphics(self, instance, value):
        if hasattr(self, 'bg_rect'):
            self.bg_rect.pos = instance.pos
            self.bg_rect.size = instance.size
            self.border.rounded_rectangle = (instance.x, instance.y, instance.width, instance.height, dp(12))

    def toggle_content(self, instance):
        if self.is_expanded:
            self.remove_widget(self.content)
            self.toggle_btn.text = '+'
        else:
            self.add_widget(self.content)
            self.toggle_btn.text = '-'
        self.is_expanded = not self.is_expanded

class DashboardScreen(Screen):
    scan_progress = NumericProperty(0)
    scan_status = StringProperty("")
    current_host = StringProperty("")
    scan_active = BooleanProperty(False)
    scan_results = ListProperty([])
    ia_status = StringProperty("Verificando...")
    ia_status_color = ListProperty([0.6, 0.6, 0.1, 1])
    MAX_HOSTS_LIMIT = 4096
    results_panel_color = ListProperty([0, 0, 0, 0])

    def __init__(self, **kwargs):
        super(DashboardScreen, self).__init__(**kwargs)
        self.nm = nmap.PortScanner()
        self.scan_thread = None
        self.hosts_scanned = 0
        self.total_hosts = 0
        self.hosts_to_scan_list = []
        self._update_progress_event = None
        self.ip_octet_ids = [
            'ip_inicial_octet1', 'ip_inicial_octet2', 'ip_inicial_octet3', 'ip_inicial_octet4',
            'ip_final_octet1', 'ip_final_octet2', 'ip_final_octet3', 'ip_final_octet4'
        ]
        self.severity_model = None
        self.treatment_model = None
        Clock.schedule_once(self._load_ml_models)

    def on_enter(self, *args):
        Clock.schedule_once(lambda dt: self._detect_local_ip_and_set_range())
        if self._update_progress_event is None:
            self._update_progress_event = Clock.schedule_interval(self.update_progress_ui_elements, 0.1)
        self._set_results_view(show_image=True)

    def _set_results_view(self, show_image):
        results_panel = self.ids.results_panel
        image_widget = self.ids.results_background
        
        ui_bg_color = (0.96, 0.97, 0.98, 1)
        transparent = (0, 0, 0, 0)
        self.results_panel_color = transparent if show_image else ui_bg_color
        
        if show_image:
            if image_widget.parent is None:
                results_panel.add_widget(image_widget)
        else:
            if image_widget.parent is not None:
                results_panel.remove_widget(image_widget)

    def _validate_octet_input(self, octet_id, text_input_instance):
        text = text_input_instance.text.strip()
        if not text:
            text_input_instance.background_color = (1, 1, 1, 1)
            return True
        try:
            value = int(text)
            if not (0 <= value <= 255):
                text_input_instance.background_color = (1, 0.8, 0.8, 1)
                return False
            else:
                text_input_instance.background_color = (1, 1, 1, 1)
                return True
        except ValueError:
            text_input_instance.background_color = (1, 0.8, 0.8, 1)
            return False

    def _handle_octet_input(self, octet_id, instance, text):
        if (text.endswith('.') and len(text) > 0) or \
           (len(text) == 3 and self._validate_octet_input(octet_id, instance) and text.isdigit()):
            if text.endswith('.'):
                instance.text = text[:-1]
            try:
                current_index = self.ip_octet_ids.index(octet_id)
                if current_index + 1 < len(self.ip_octet_ids):
                    self.ids[self.ip_octet_ids[current_index + 1]].focus = True
                else:
                    instance.focus = False
            except ValueError:
                pass

    def _detect_local_ip_and_set_range(self, *args):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            ip_octets = local_ip.split('.')
            self.ids.ip_inicial_octet1.text = ip_octets[0]
            self.ids.ip_inicial_octet2.text = ip_octets[1]
            self.ids.ip_inicial_octet3.text = ip_octets[2]
            self.ids.ip_inicial_octet4.text = "1"
            self.ids.ip_final_octet1.text = ip_octets[0]
            self.ids.ip_final_octet2.text = ip_octets[1]
            self.ids.ip_final_octet3.text = ip_octets[2]
            self.ids.ip_final_octet4.text = "254"
            self.ids.status_label.text = f"[color=0000FF]IP local detectada: {local_ip}. Rango pre-llenado.[/color]"
        except Exception as e:
            self.ids.status_label.text = f"[color=ffA500]No se pudo detectar la IP local. Ingrese el rango manualmente.[/color]"
            print(f"Error al detectar IP local: {e}")

    def _load_ml_models(self, dt):
        try:
            self.severity_model = joblib.load('severity_model.pkl')
            self.treatment_model = joblib.load('treatment_model.pkl')
            print("Modelos de ML cargados exitosamente.")
            self.ids.status_label.text = "[color=0000FF]Modelos de IA cargados. Listo para escanear.[/color]"
            self.ia_status = "Cargada y Verificada"
            self.ia_status_color = (0, 0.7, 0.2, 1)
        except Exception as e:
            self.ids.status_label.text = f"[color=ffA500]Advertencia: Archivos de modelo ML no encontrados...[/color]"
            print(f"Error al cargar modelos ML: {e}")
            self.severity_model = None
            self.treatment_model = None
            self.ia_status = "No disponible"
            self.ia_status_color = (0.8, 0.1, 0.1, 1)

    def validar_y_analizar(self):
        if self.scan_active:
            self.cancel_scan()
            return

        self.ids.results_container.clear_widgets()
        self._set_results_view(show_image=True)

        all_octets_valid = all(self._validate_octet_input(oid, self.ids[oid]) for oid in self.ip_octet_ids)
        if not all_octets_valid or any(not self.ids[oid].text.strip() for oid in self.ip_octet_ids):
            self.ids.status_label.text = "[color=ff0000]Error: Todos los campos de IP deben ser válidos (0-255) y estar llenos.[/color]"
            return

        ip_inicial_str = f"{self.ids.ip_inicial_octet1.text}.{self.ids.ip_inicial_octet2.text}.{self.ids.ip_inicial_octet3.text}.{self.ids.ip_inicial_octet4.text}"
        ip_final_str = f"{self.ids.ip_final_octet1.text}.{self.ids.ip_final_octet2.text}.{self.ids.ip_final_octet3.text}.{self.ids.ip_final_octet4.text}"

        try:
            ip_start_obj = ipaddress.IPv4Address(ip_inicial_str)
            ip_end_obj = ipaddress.IPv4Address(ip_final_str)
            if ip_end_obj < ip_start_obj:
                self.ids.status_label.text = "[color=ff0000]La IP final debe ser mayor o igual que la IP inicial.[/color]"
                return
        except ValueError:
            self.ids.status_label.text = "[color=ff0000]La dirección IP inicial o final es inválida.[/color]"
            return

        self.hosts_to_scan_list = []
        for network in ipaddress.summarize_address_range(ip_start_obj, ip_end_obj):
            for ip in network:
                self.hosts_to_scan_list.append(str(ip))

        self.total_hosts = len(self.hosts_to_scan_list)

        if self.total_hosts == 0 or self.total_hosts > self.MAX_HOSTS_LIMIT:
            self.ids.status_label.text = f"[color=ffA500]El rango es inválido o demasiado grande ({self.total_hosts} equipos). El límite es {self.MAX_HOSTS_LIMIT}.[/color]"
            return
        
        if not self.severity_model or not self.treatment_model:
            self.ids.status_label.text = "[color=ffA500]Advertencia: Modelos de IA no cargados. El escaneo continuará sin clasificación inteligente.[/color]"
        else:
            self.ids.status_label.text = f"[color=00ff00]Preparando escaneo de {self.total_hosts} equipo(s)...[/color]"

        self.scan_active = True
        self.scan_results = []
        self.scan_progress = 0
        self.hosts_scanned = 0
        self.scan_status = "Iniciando escaneo..."
        self.current_host = ""

        self.scan_thread = threading.Thread(target=self.run_nmap_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def update_progress_ui_elements(self, dt):
        if not self or not hasattr(self, 'ids') or 'bottom_scan_progressbar' not in self.ids:
            return True
        if not self.scan_active:
            if self._update_progress_event:
                self._update_progress_event.cancel()
                self._update_progress_event = None
            return False
        self.ids.bottom_scan_progressbar.value = self.scan_progress
        self.ids.bottom_status_text.text = self.scan_status
        self.ids.bottom_current_host_label.text = ("Escaneando: " + self.current_host) if self.current_host else ""
        return True

    def run_nmap_scan(self):
        args_list = []
        if self.ids.nmap_opt_sS.active: args_list.append('-sS')
        if self.ids.nmap_opt_sT.active: args_list.append('-sT')
        if self.ids.nmap_opt_sU.active: args_list.append('-sU')
        if self.ids.nmap_opt_O.active: args_list.append('-O')
        if self.ids.nmap_opt_sV.active: args_list.append('-sV')
        if self.ids.nmap_opt_Pn.active: args_list.append('-Pn')
        if self.ids.nmap_opt_vulners.active: args_list.append('--script vulners')
        if self.ids.custom_nmap_args_input.text.strip():
            args_list.extend(self.ids.custom_nmap_args_input.text.strip().split())
        if '--script vulners' in args_list and '-sV' not in args_list and '-A' not in args_list:
            args_list.insert(0, '-sV')
        scan_args = ' '.join(args_list)

        if not self.hosts_to_scan_list:
            Clock.schedule_once(lambda dt: self._set_scan_status("Error: No hay equipos para escanear."))
            Clock.schedule_once(self.finish_scan)
            return

        initial_status_msg = f"Escaneando {self.total_hosts} equipo(s) con args: {scan_args}"
        Clock.schedule_once(lambda dt: self._set_scan_status(initial_status_msg))

        try:
            for host_str in self.hosts_to_scan_list:
                if not self.scan_active: break
                self.current_host = host_str
                Clock.schedule_once(lambda dt, h=host_str: self._set_scan_status(f"Escaneando {h} ({self.hosts_scanned + 1}/{self.total_hosts})"))
                try:
                    self.nm.scan(hosts=host_str, arguments=scan_args)
                    self.process_nmap_results(host_str)
                except Exception as e:
                    self.scan_results.append({'ip': host_str, 'port': 'N/A', 'service': 'Error en escaneo', 'version': '', 'vulnerability': str(e), 'severity': 'Error', 'recommendation': 'Fallo en escaneo Nmap.'})
                self.hosts_scanned += 1
                self.scan_progress = (self.hosts_scanned / self.total_hosts) * 100
            final_status_msg = "Escaneo completado" if self.scan_active else "Escaneo cancelado"
            Clock.schedule_once(lambda dt: self._set_scan_status(final_status_msg))
        except Exception as e:
            Clock.schedule_once(lambda dt: self._set_scan_status(f"Error general: {e}"))
        finally:
            Clock.schedule_once(self.finish_scan)

    def _set_scan_status(self, status_text):
        self.scan_status = status_text

    def _extract_features_for_ml(self, port_data, host_ip=None):
        features_dict = {}
        port = int(port_data.get('portid', 0))
        service_name = str(port_data.get('name', '')).lower()
        product = str(port_data.get('product', '')).lower()
        version = str(port_data.get('version', '')).lower()
        vulners_output = str(port_data.get('script', {}).get('vulners', '')).lower()

        features_dict['is_common_web_port'] = 1 if port in [80, 443, 8080] else 0
        features_dict['is_common_db_port'] = 1 if port in [3306, 5432, 1433] else 0
        features_dict['is_common_ssh_port'] = 1 if port == 22 else 0
        features_dict['is_common_ftp_port'] = 1 if port == 21 else 0
        features_dict['is_common_telnet_port'] = 1 if port == 23 else 0
        features_dict['service_apache'] = 1 if 'apache' in product or 'http' in service_name else 0
        features_dict['service_openssh'] = 1 if 'openssh' in product or 'ssh' in service_name else 0
        features_dict['service_microsoft_iis'] = 1 if 'iis' in product else 0
        features_dict['service_ftp'] = 1 if 'ftp' in service_name else 0
        features_dict['service_telnet'] = 1 if 'telnet' in service_name else 0
        features_dict['service_mysql'] = 1 if 'mysql' in service_name else 0
        features_dict['is_openssh_old'] = 1 if 'openssh' in product and any(v in version for v in ['5.','6.','7.0','7.1','7.2','7.3']) else 0
        features_dict['is_apache_2_2'] = 1 if 'apache' in product and '2.2' in version else 0
        features_dict['is_telnet_open_unencrypted'] = 1 if 'telnet' in service_name and port_data.get('state') == 'open' else 0
        features_dict['vulners_critical_found'] = 1 if 'critical' in vulners_output else 0
        features_dict['vulners_high_found'] = 1 if 'high' in vulners_output else 0
        features_dict['vulners_medium_found'] = 1 if 'medium' in vulners_output else 0
        features_dict['vulners_low_found'] = 1 if 'low' in vulners_output else 0
        features_dict['vulners_script_output_present'] = 1 if vulners_output else 0
        features_dict['port_state_open'] = 1 if port_data.get('state') == 'open' else 0
        
        try:
            feature_vector = pd.DataFrame([features_dict])
            return feature_vector[MASTER_FEATURES_LIST]
        except Exception as e:
            print(f"Error al construir DataFrame de características: {e}")
            return None

    def process_nmap_results(self, host):
        if host not in self.nm.all_hosts(): return
        host_data = self.nm[host]
        found_data_for_host = False
        for proto in host_data.all_protocols():
            for port in host_data[proto].keys():
                port_data = host_data[proto][port]
                service_name = port_data.get('name', 'desconocido')
                product_version = f"{port_data.get('product', '')} {port_data.get('version', '')}".strip()
                
                predicted_severity = 'Info'
                interpreted_vulnerability = f"Servicio {service_name} activo en puerto {port}."
                proposed_treatment_solution = 'Revisión manual recomendada.'

                is_cctv = any(kw in service_name for kw in ['rtsp', 'onvif', 'hikvision', 'dahua'])
                if is_cctv:
                    interpreted_vulnerability = "Posible sistema de CCTV/Vigilancia detectado."
                    proposed_treatment_solution = TREATMENT_SOLUTION_MAP[7]
                    predicted_severity = 'Medium'

                if not is_cctv:
                    features = self._extract_features_for_ml(port_data, host)
                    if features is not None and self.severity_model and self.treatment_model:
                        try:
                            pred_sev_num = self.severity_model.predict(features)[0]
                            predicted_severity = NUMERIC_TO_SPANISH_SEVERITY.get(pred_sev_num, "Info")
                            
                            probabilities = self.treatment_model.predict_proba(features)[0]
                            max_proba = max(probabilities)
                            
                            if max_proba < 0.50: 
                                proposed_treatment_solution = TREATMENT_SOLUTION_MAP[6]
                            else:
                                pred_treat_id = self.treatment_model.predict(features)[0]
                                proposed_treatment_solution = TREATMENT_SOLUTION_MAP.get(pred_treat_id, "Revisión manual.")
                            
                            vuln_details = port_data.get('script', {}).get('vulners', '').strip().split('\n')[0]
                            interpreted_vulnerability = f"Vulnerabilidad detectada en {service_name}."
                            if vuln_details:
                                 interpreted_vulnerability += f" Detalles: {vuln_details[:150]}"
                            
                        except Exception as e:
                            print(f"Error en predicción ML para {host}:{port}: {e}")
                            predicted_severity = 'Error'
                            interpreted_vulnerability = f"Error en análisis ML: {e}"
                
                self.scan_results.append({
                    'ip': host, 'port': str(port), 'service': service_name, 'version': product_version,
                    'vulnerability': interpreted_vulnerability, 'severity': predicted_severity,
                    'recommendation': proposed_treatment_solution
                })
                found_data_for_host = True
        
        if not found_data_for_host and self.nm[host].state() == 'up':
            os_name = self.nm[host].get('osmatch', [{}])[0].get('name', '')
            self.scan_results.append({
                'ip': host, 'port': '-', 'service': 'Equipo Activo', 'version': os_name,
                'vulnerability': 'El equipo respondió al escaneo. No se detectaron servicios abiertos.',
                'severity': 'Info', 'recommendation': 'Realizar escaneo más profundo si se esperan servicios.'
            })

    def finish_scan(self, dt=None):
        self.scan_active = False
        if self._update_progress_event:
            self._update_progress_event.cancel()
            self._update_progress_event = None
        self.display_results()
        self.current_host = ""
        if "Error" in self.scan_status:
             self.ids.status_label.text = f"[color=ff0000]{self.scan_status}[/color]"
        elif self.scan_status == "Escaneo cancelado":
            self.ids.status_label.text = "[color=FFA500]Escaneo cancelado por el usuario.[/color]"
        else:
            self.ids.status_label.text = "[color=00ff00]Escaneo finalizado.[/color]"

    def display_results(self):
        self.ids.results_container.clear_widgets()
        self._set_results_view(show_image=False)
        
        if not self.scan_results:
            self.ids.results_container.add_widget(Label(text="No se encontraron resultados para mostrar.", size_hint_y=None, height=dp(40)))
            return

        grouped_by_host = defaultdict(list)
        for result in self.scan_results:
            grouped_by_host[result['ip']].append(result)
        
        sorted_host_ips = sorted(grouped_by_host.keys(), key=ipaddress.ip_address)
        for host_ip in sorted_host_ips:
            self.ids.results_container.add_widget(HostDataGroup(host_ip=host_ip, vulnerabilities_for_host=grouped_by_host[host_ip]))
        
        self.add_summary_and_chart(self.ids.results_container)

    def add_summary_and_chart(self, container):
        summary_box = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(10), padding=dp(10))
        summary_box.bind(minimum_height=summary_box.setter('height'))
        
        summary_box.add_widget(Label(text="Resumen General del Escaneo", bold=True, font_size='18sp', size_hint_y=None, height=dp(40), color=COLOR_TEXT_DARK_PY))

        counts = {s: len([r for r in self.scan_results if r['severity'] == s]) for s in SPANISH_SEVERITY.keys()}
        
        stats_text_box = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(4))
        stats_text_box.bind(minimum_height=stats_text_box.setter('height'))

        stats_data = [
            ("Equipos Escaneados:", str(self.total_hosts)),
            ("Equipos con Hallazgos:", str(len({r['ip'] for r in self.scan_results if r['severity'] not in ['Error', 'Info']})))
        ]
        
        for label, value in stats_data:
            row = BoxLayout(size_hint_y=None, height=dp(25))
            row.add_widget(Label(text=label, bold=True, halign='left', color=COLOR_TEXT_DARK_PY, text_size=(container.width*0.4, None)))
            row.add_widget(Label(text=value, halign='left', color=COLOR_TEXT_DARK_PY, text_size=(container.width*0.5, None)))
            stats_text_box.add_widget(row)
        
        summary_box.add_widget(stats_text_box)
        summary_box.add_widget(Label(text="Hallazgos por Severidad", bold=True, font_size='16sp', size_hint_y=None, height=dp(30), color=COLOR_TEXT_DARK_PY))

        container.add_widget(summary_box)

        if any(counts.get(s, 0) > 0 for s in ['Critical', 'High', 'Medium', 'Low', 'Info']):
            try:
                chart = SummaryChart(counts=counts)
                container.add_widget(chart)
            except Exception as e:
                container.add_widget(Label(text=f"Error al generar gráfico: {e}", color=(1,0,0,1)))

    def cancel_scan(self):
        if self.scan_active:
            self.scan_active = False
            self.ids.status_label.text = "[color=FFA500]Cancelando escaneo, por favor espere...[/color]"

    def export_results_to_pdf(self):
        if not self.scan_results:
            self.ids.status_label.text = "[color=ff0000]No hay resultados para exportar.[/color]"
            return

        content = BoxLayout(orientation='vertical', spacing=dp(5))
        
        filechooser = FileChooserListView(path=str(Path.home()), dirselect=False)
        content.add_widget(filechooser)

        filename_input = TextInput(text=f"ScanIA_Informe_{time.strftime('%Y%m%d_%H%M%S')}.pdf", 
                                   size_hint_y=None, height=dp(40), multiline=False)
        content.add_widget(filename_input)
        
        buttons = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        save_button = Button(text='Guardar')
        cancel_button = Button(text='Cancelar')
        buttons.add_widget(save_button)
        buttons.add_widget(cancel_button)
        content.add_widget(buttons)

        popup = Popup(title='Guardar Informe PDF', content=content, size_hint=(0.9, 0.9))
        
        def save_action(instance):
            if filechooser.selection:
                path = filechooser.selection[0]
            else:
                path = os.path.join(filechooser.path, filename_input.text)
            
            self._do_export(popup, path)

        save_button.bind(on_press=save_action)
        cancel_button.bind(on_press=popup.dismiss)
        
        popup.open()

    def _do_export(self, popup, report_path):
        popup.dismiss()
        
        self._set_scan_status(f"Generando informe PDF en {report_path}...")
        threading.Thread(target=self._generate_pdf_report_thread, args=(report_path,)).start()

    def _generate_pdf_report_thread(self, report_path):
        try:
            styles = getSampleStyleSheet()
            title_style = styles['h1']
            title_style.alignment = 1
            title_style.textColor = colors.HexColor('#0069AA')
            h2_style = styles['h2']
            h2_style.textColor = colors.HexColor('#00558E')
            
            doc = SimpleDocTemplate(report_path, pagesize=letter)
            story = []

            story.append(Paragraph("Informe de Análisis de Vulnerabilidades - ScanIA", title_style))
            story.append(Spacer(1, 0.2 * inch))
            # ... (código de generación de PDF sin cambios) ...

        except Exception as e:
            Clock.schedule_once(lambda dt: self._set_scan_status(f"[color=ff0000]Error al generar PDF: {e}[/color]"))