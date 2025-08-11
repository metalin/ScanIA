# screens.py
# VERSIÓN ESTABLE Y CORREGIDA (con KeyError solucionado)

import nmap, threading, ipaddress, time, os, socket, json, numpy as np
from collections import defaultdict
from pathlib import Path
import joblib
import pandas as pd
from sklearn.metrics.pairwise import cosine_similarity

from kivy.app import App
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import StringProperty, NumericProperty, BooleanProperty, ListProperty, BoundedNumericProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.image import Image
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar
from kivy.uix.screenmanager import Screen
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget
from kivy.graphics import Color, Line, Rectangle, RoundedRectangle

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch

Builder.load_file("gui/layout.kv")
Builder.load_file("gui/helppopup.kv")
Builder.load_file("gui/aboutpopup.kv") # <-- LÍNEA AÑADIDA

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

SPANISH_SEVERITY = {"Critical": "Crítica", "High": "Alta", "Medium": "Media", "Low": "Baja", "Info": "Informativa", "Error": "Error"}
COLOR_TEXT_DARK_PY = (0.1, 0.1, 0.1, 1)

try:
    with open('model_maps.json', 'r') as f:
        maps = json.load(f)
        SEVERITY_MAP_FROM_ID = {v: k for k, v in maps['severities'].items()}
        SOLUTION_MAP_FROM_ID = {v: k for k, v in maps['solutions'].items()}
        PORT_COLUMNS = maps['port_columns']
except FileNotFoundError:
    print("ADVERTENCIA: 'model_maps.json' no encontrado. La IA no funcionará correctamente.")
    SEVERITY_MAP_FROM_ID, SOLUTION_MAP_FROM_ID, PORT_COLUMNS = {}, {}, []


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
        colors = {'Critical': [1,0.2,0.2,1], 'High': [1,0.5,0.2,1], 'Medium': [0.9,0.7,0,1], 'Low': [0.2,0.6,0.2,1], 'Info': [0.25,0.41,0.88,1]}
        
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
            Color(0.96,0.97,1,1)
            self.bg_rect = RoundedRectangle(size=self.size, pos=self.pos, radius=[dp(12)])
            Color(0.8,0.82,0.9,1)
            self.border = Line(rounded_rectangle=(self.x, self.y, self.width, self.height, dp(12)), width=1.1)
        self.bind(pos=self._update_graphics, size=self._update_graphics)
        
        ip_header_layout = BoxLayout(size_hint_y=None, height=dp(45), spacing=dp(10), padding=[dp(12),0,dp(12),0])
        ip_label = Label(text=f"Equipo: {host_ip}", bold=True, font_size='17sp', color=COLOR_TEXT_DARK_PY, size_hint_x=0.8, halign='left', valign='middle')
        ip_label.bind(width=lambda i,v: setattr(i, 'text_size', (v, None)))
        ip_header_layout.add_widget(ip_label)
        
        self.toggle_btn = Button(text='-', size_hint_x=0.2, size_hint_y=None, height=dp(38), background_normal='', background_color=(0/255, 85/255, 142/255, 1))
        self.toggle_btn.bind(on_press=self.toggle_content)
        ip_header_layout.add_widget(self.toggle_btn)
        self.add_widget(ip_header_layout)
        
        self.content = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(6), padding=[dp(12),dp(8)])
        self.content.bind(minimum_height=self.content.setter('height'))
        self.is_expanded = True
        
        if not vulnerabilities_for_host:
            self.content.add_widget(Label(text="(No se encontraron vulnerabilidades)", size_hint_y=None, height=dp(30), halign='left', color=(0.4,0.4,0.4,1)))
        else:
            headers=[("Puerto",0.08),("Servicio",0.15),("Descripción",0.27),("Severidad",0.15),("Tratamiento Propuesto",0.35)]
            header_row = BoxLayout(size_hint_y=None, height=dp(35), spacing=dp(5))
            for text, size_hint in headers:
                lbl = Label(text=text, size_hint_x=size_hint, bold=True, color=COLOR_TEXT_DARK_PY, font_size='13sp', halign='left', valign='middle')
                lbl.bind(width=lambda i,v: setattr(i,'text_size',(v,None)))
                header_row.add_widget(lbl)
            self.content.add_widget(header_row)
            
            sorted_vulns = sorted(vulnerabilities_for_host, key=lambda x: {'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4,'Error':5}.get(x['severity'],99))
            
            for vuln in sorted_vulns:
                row = BoxLayout(size_hint_y=None, spacing=dp(5)); row.bind(minimum_height=row.setter('height'))
                def create_label(text, size_hint_x, color=COLOR_TEXT_DARK_PY, bold=False):
                    lbl = Label(text=str(text), size_hint_x=size_hint_x, size_hint_y=None, color=color, bold=bold, font_size='12sp', halign='left', valign='top')
                    lbl.bind(width=lambda i,v: setattr(i,'text_size',(v,None)))
                    lbl.bind(texture_size=lambda i,v: setattr(i,'height',v[1]))
                    return lbl
                row.add_widget(create_label(vuln['port'], 0.08))
                row.add_widget(create_label(vuln['service'], 0.15))
                row.add_widget(create_label(vuln['vulnerability'], 0.27))
                s_key = vuln['severity']
                s_text = SPANISH_SEVERITY.get(s_key, s_key)
                s_color = {'Critical':(1,0,0,1),'High':(1,0.5,0,1),'Medium':(0.9,0.7,0,1),'Low':(0,0.6,0,1),'Info':(0.2,0.5,0.8,1)}.get(s_key,(0.2,0.2,0.2,1))
                row.add_widget(create_label(s_text, 0.15, color=s_color, bold=True))
                row.add_widget(create_label(vuln.get('recommendation', 'N/A'), 0.35))
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

class HelpPopup(Popup):
    help_text = StringProperty('')

# --- CLASE AÑADIDA ---
class AboutPopup(Popup):
    about_text = StringProperty('')
# ---------------------


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
        self.nm = None
        self.scan_thread = None
        self.hosts_scanned = 0
        self.total_hosts = 0
        self.hosts_to_scan_list = []
        self._update_progress_event = None
        self.ip_octet_ids = [
            'ip_inicial_octet1', 'ip_inicial_octet2', 'ip_inicial_octet3', 'ip_inicial_octet4',
            'ip_final_octet1', 'ip_final_octet2', 'ip_final_octet3', 'ip_final_octet4'
        ]
        self.knowledge_base = None
        Clock.schedule_once(self._load_knowledge_base)

    def on_enter(self, *args):
        Clock.schedule_once(lambda dt: self._detect_local_ip_and_set_range())
        self._set_results_view(show_image=True)

    def _set_results_view(self, show_image):
        if show_image:
            self.ids.results_background.opacity = 1
            self.results_panel_color = [0, 0, 0, 0]
        else:
            self.ids.results_background.opacity = 0
            self.results_panel_color = [245/255, 248/255, 252/255, 1]

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
        if (text.endswith('.') and len(text) > 0) or (len(text) == 3 and self._validate_octet_input(octet_id, instance) and text.isdigit()):
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
            octets = local_ip.split('.')
            self.ids.ip_inicial_octet1.text, self.ids.ip_inicial_octet2.text, self.ids.ip_inicial_octet3.text = octets[0], octets[1], octets[2]
            self.ids.ip_inicial_octet4.text = "1"
            self.ids.ip_final_octet1.text, self.ids.ip_final_octet2.text, self.ids.ip_final_octet3.text = octets[0], octets[1], octets[2]
            self.ids.ip_final_octet4.text = "254"
            self.ids.status_label.text = f"[color=0000FF]IP local detectada: {local_ip}. Rango pre-llenado.[/color]"
        except Exception as e:
            self.ids.status_label.text = f"[color=ffA500]No se pudo detectar IP local.[/color]"
            print(f"Error al detectar IP local: {e}")

    def _load_knowledge_base(self, dt):
        try:
            self.knowledge_base = joblib.load('knowledge_base.pkl')
            print("Base de conocimiento de IA cargada exitosamente.")
            self.ids.status_label.text = "[color=0000FF]Base de conocimiento cargada.[/color]"
            self.ia_status, self.ia_status_color = "Cargada y Verificada", (0, 0.7, 0.2, 1)
        except Exception as e:
            print(f"Error al cargar la base de conocimiento: {e}")
            self.knowledge_base = None
            self.ia_status, self.ia_status_color = "No disponible", (0.8, 0.1, 0.1, 1)

    def validar_y_analizar(self):
        if self.scan_active:
            self.cancel_scan()
            return

        self.ids.results_container.clear_widgets()
        self._set_results_view(show_image=True)

        if not all(self._validate_octet_input(oid, self.ids[oid]) for oid in self.ip_octet_ids) or any(not self.ids[oid].text.strip() for oid in self.ip_octet_ids):
            self.ids.status_label.text = "[color=ff0000]Error: Todos los campos de IP son requeridos y deben ser válidos.[/color]"
            return

        ip_i = f"{self.ids.ip_inicial_octet1.text}.{self.ids.ip_inicial_octet2.text}.{self.ids.ip_inicial_octet3.text}.{self.ids.ip_inicial_octet4.text}"
        ip_f = f"{self.ids.ip_final_octet1.text}.{self.ids.ip_final_octet2.text}.{self.ids.ip_final_octet3.text}.{self.ids.ip_final_octet4.text}"

        try:
            if ipaddress.IPv4Address(ip_f) < ipaddress.IPv4Address(ip_i):
                self.ids.status_label.text = "[color=ff0000]La IP final debe ser mayor o igual a la inicial.[/color]"
                return
        except ValueError:
            self.ids.status_label.text = "[color=ff0000]Una o más direcciones IP no son válidas.[/color]"
            return

        self.hosts_to_scan_list = [str(ip) for net in ipaddress.summarize_address_range(ipaddress.IPv4Address(ip_i), ipaddress.IPv4Address(ip_f)) for ip in net]
        self.total_hosts = len(self.hosts_to_scan_list)

        if self.total_hosts == 0 or self.total_hosts > self.MAX_HOSTS_LIMIT:
            self.ids.status_label.text = f"[color=ffA500]Rango inválido o demasiado grande. Límite: {self.MAX_HOSTS_LIMIT} equipos.[/color]"
            return
        
        self.nm = nmap.PortScanner()

        if self._update_progress_event is None:
            self._update_progress_event = Clock.schedule_interval(self.update_progress_ui_elements, 0.1)

        self.scan_active = True
        self.scan_results = []
        self.scan_progress = 0
        self.hosts_scanned = 0
        self.scan_status = "Iniciando escaneo..."
        self.current_host = ""

        self.scan_thread = threading.Thread(target=self.run_nmap_scan, daemon=True)
        self.scan_thread.start()

    def update_progress_ui_elements(self, dt):
        if not self.scan_active:
            return True

        if hasattr(self, 'ids') and self.ids:
            # Corregido: Referencia al ProgressBar correcto
            if 'bottom_scan_progressbar' in self.ids:
                self.ids.bottom_scan_progressbar.value = self.scan_progress
            self.ids.bottom_status_text.text = self.scan_status
            self.ids.bottom_current_host_label.text = f"Escaneando: {self.current_host}" if self.current_host else ""
        return True

    def run_nmap_scan(self):
        args_map = {
            '-sS': 'nmap_opt_sS', '-sT': 'nmap_opt_sT', '-sU': 'nmap_opt_sU',
            '-O': 'nmap_opt_O', '-sV': 'nmap_opt_sV', '-Pn': 'nmap_opt_Pn',
            '--script vulners': 'nmap_opt_vulners'
        }
        args_list = [opt for opt, flag in args_map.items() if self.ids[flag].active]
        if self.ids.custom_nmap_args_input.text.strip():
            args_list.extend(self.ids.custom_nmap_args_input.text.strip().split())
        
        scan_args = ' '.join(args_list)
        if '--script vulners' in scan_args and '-sV' not in scan_args and '-A' not in scan_args:
            scan_args = '-sV ' + scan_args
        
        for i, host_str in enumerate(self.hosts_to_scan_list):
            if not self.scan_active:
                break
            self.current_host = host_str
            self.scan_status = f"Escaneando {host_str} ({i + 1}/{self.total_hosts})"
            try:
                self.nm.scan(hosts=host_str, arguments=scan_args)
                self.process_nmap_results(host_str)
            except Exception as e:
                self.scan_results.append({
                    'ip': host_str, 'port': 'N/A', 'service': 'Error',
                    'vulnerability': str(e), 'severity': 'Error', 'recommendation': 'Fallo en Nmap.'
                })
            self.hosts_scanned += 1
            if self.total_hosts > 0:
                self.scan_progress = (self.hosts_scanned / self.total_hosts) * 100
        
        Clock.schedule_once(self.finish_scan)

    def get_ai_recommendation(self, port_data):
        if not self.knowledge_base:
            return "Info", "Revisión manual.", "Base de conocimiento no cargada."
        try:
            service = str(port_data.get('name', '')).lower()
            product = str(port_data.get('product', '')).lower()
            vuln_text_from_nmap = str(port_data.get('script', {}).get('vulners', '')).strip().split('\n')[0]
            if not vuln_text_from_nmap:
                vuln_text_from_nmap = f"Servicio {service} activo."
            
            query_signature = f"{service} {product} {vuln_text_from_nmap}"
            
            vectorizer = self.knowledge_base['vectorizer']
            query_vector = vectorizer.transform([query_signature])
            matrix = self.knowledge_base['knowledge_matrix']
            similarity_scores = cosine_similarity(query_vector, matrix).flatten()
            best_match_index = np.argmax(similarity_scores)
            kb_df = self.knowledge_base['dataframe']
            
            match_severity = kb_df.loc[best_match_index, 'manual_severity']
            match_treatment = kb_df.loc[best_match_index, 'proposed_treatment_solution']
            match_description = kb_df.loc[best_match_index, 'vulnerability_context_description']
            
            return match_severity, match_treatment, match_description
        except Exception as e:
            print(f"Error en recomendación IA: {e}")
            return "Error", "Fallo en motor de similitud.", "No se pudo generar descripción."

    def process_nmap_results(self, host):
        if self.nm and host not in self.nm.all_hosts():
            return
        for proto in self.nm[host].all_protocols():
            for port in self.nm[host][proto].keys():
                port_data = self.nm[host][proto][port]
                sev, treat, desc = self.get_ai_recommendation(port_data)
                self.scan_results.append({
                    'ip': host, 'port': str(port), 'service': port_data.get('name', ''),
                    'vulnerability': desc, 'severity': sev, 'recommendation': treat
                })
        if self.nm and not self.nm[host].all_protocols() and self.nm[host].state() == 'up':
            self.scan_results.append({
                'ip': host, 'port': '-', 'service': 'Equipo Activo',
                'vulnerability': 'No se detectaron servicios abiertos.',
                'severity': 'Info', 'recommendation': 'Realizar escaneo más profundo.'
            })

    def finish_scan(self, dt=None):
        self.scan_active = False
        self.current_host = ""
        
        if self._update_progress_event:
            self._update_progress_event.cancel()
            self._update_progress_event = None
        
        is_cancelled = self.scan_thread is not None and self.hosts_scanned < self.total_hosts
        if is_cancelled and self.hosts_scanned > 0:
             self.scan_status = "Escaneo cancelado"
             self.ids.status_label.text = f"[color=FFA500]{self.scan_status}[/color]"
        else:
             self.scan_status = "Escaneo finalizado"
             self.ids.status_label.text = f"[color=00ff00]{self.scan_status}[/color]"
        
        self.display_results()

    def display_results(self):
        self.ids.results_container.clear_widgets()
        self._set_results_view(show_image=False)
        if not self.scan_results:
            self.ids.results_container.add_widget(Label(text="No se encontraron resultados.", size_hint_y=None, height=dp(40)))
            return
        
        grouped_by_host = defaultdict(list)
        for result in self.scan_results:
            grouped_by_host[result['ip']].append(result)
        
        for host_ip in sorted(grouped_by_host.keys(), key=ipaddress.ip_address):
            self.ids.results_container.add_widget(HostDataGroup(host_ip=host_ip, vulnerabilities_for_host=grouped_by_host[host_ip]))
        
        self.add_summary_and_chart(self.ids.results_container)

    def add_summary_and_chart(self, container):
        summary_box = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(10), padding=dp(10))
        summary_box.bind(minimum_height=summary_box.setter('height'))
        summary_box.add_widget(Label(text="Resumen General del Escaneo", bold=True, font_size='18sp', size_hint_y=None, height=dp(40), color=COLOR_TEXT_DARK_PY))
        
        counts = {s: len([r for r in self.scan_results if r['severity'] == s]) for s in SPANISH_SEVERITY.keys()}
        stats_data = [
            ("Equipos Escaneados:", str(self.total_hosts)),
            ("Equipos con Hallazgos:", str(len({r['ip'] for r in self.scan_results if r['severity'] not in ['Error', 'Info']})))
        ]
        
        stats_box = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(4))
        stats_box.bind(minimum_height=stats_box.setter('height'))
        for label, value in stats_data:
            row = BoxLayout(size_hint_y=None, height=dp(25))
            row.add_widget(Label(text=label, bold=True, halign='left', text_size=(container.width * 0.4, None), color=COLOR_TEXT_DARK_PY))
            row.add_widget(Label(text=value, halign='left', text_size=(container.width * 0.5, None), color=COLOR_TEXT_DARK_PY))
            stats_box.add_widget(row)
        
        summary_box.add_widget(stats_box)
        summary_box.add_widget(Label(text="Hallazgos por Severidad", bold=True, font_size='16sp', size_hint_y=None, height=dp(30), color=COLOR_TEXT_DARK_PY))
        
        if any(counts.get(s, 0) > 0 for s in ['Critical', 'High', 'Medium', 'Low', 'Info']):
            try:
                chart = SummaryChart(counts=counts)
                container.add_widget(chart, index=0)
            except Exception as e:
                container.add_widget(Label(text=f"Error al generar gráfico: {e}", color=(1, 0, 0, 1)), index=0)

        container.add_widget(summary_box, index=0)

    def cancel_scan(self):
        if self.scan_active:
            self.scan_active = False
            self.scan_thread = None
            self.ids.status_label.text = "[color=FFA500]Cancelando escaneo...[/color]"

    def export_results_to_pdf(self):
        if not self.scan_results:
            self.ids.status_label.text = "[color=ff0000]No hay resultados para exportar.[/color]"
            return

        content = BoxLayout(orientation='vertical', spacing=dp(5))
        try:
            default_path = str(Path.home())
            if not os.path.exists(default_path) or not os.access(default_path, os.W_OK):
                default_path = "/tmp"
        except Exception:
            default_path = "."

        filechooser = FileChooserListView(path=default_path, dirselect=False)
        content.add_widget(filechooser)
        filename_input = TextInput(text=f"ScanIA_Informe_{time.strftime('%Y%m%d_%H%M%S')}.pdf", size_hint_y=None, height=dp(40), multiline=False)
        content.add_widget(filename_input)
        buttons = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        save_button = Button(text='Guardar')
        cancel_button = Button(text='Cancelar')
        buttons.add_widget(save_button)
        buttons.add_widget(cancel_button)
        content.add_widget(buttons)
        popup = Popup(title='Guardar Informe PDF', content=content, size_hint=(0.9, 0.9))
        
        def save_action(instance):
            save_path = filechooser.path
            if filechooser.selection:
                selected_file = filechooser.selection[0]
                save_path = os.path.dirname(selected_file) if not os.path.isdir(selected_file) else selected_file
            path = os.path.join(save_path, filename_input.text)
            self._do_export(popup, path)
            
        save_button.bind(on_press=save_action)
        cancel_button.bind(on_press=popup.dismiss)
        popup.open()

    def _do_export(self, popup, report_path):
        popup.dismiss()
        self.scan_status = f"Generando informe PDF..."
        threading.Thread(target=self._generate_pdf_report_thread, args=(report_path,), daemon=True).start()

    def _generate_pdf_report_thread(self, report_path):
        try:
            doc = SimpleDocTemplate(report_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            title_style = styles['h1']; title_style.alignment = 1; title_style.textColor = colors.HexColor('#0069AA')
            h2_style = styles['h2']; h2_style.textColor = colors.HexColor('#00558E')

            story.append(Paragraph("Informe de Análisis de Vulnerabilidades - ScanIA", title_style))
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph(f"Fecha del Informe: {time.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            if self.hosts_to_scan_list:
                story.append(Paragraph(f"Rango Escaneado: {self.hosts_to_scan_list[0]} - {self.hosts_to_scan_list[-1]}", styles['Normal']))
            story.append(Spacer(1, 0.3 * inch))
            story.append(Paragraph("Resumen General", h2_style))
            story.append(Spacer(1, 0.1 * inch))
            
            counts = {s: len([r for r in self.scan_results if r['severity'] == s]) for s in SPANISH_SEVERITY.keys()}
            summary_data = [['Métrica', 'Cantidad']] + [[f"Severidad: {SPANISH_SEVERITY[s]}", str(counts[s])] for s in ['Critical', 'High', 'Medium', 'Low', 'Info']]
            table = Table(summary_data)
            table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0069AA')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke), ('ALIGN', (0, 0), (-1, -1), 'LEFT'), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('GRID', (0, 0), (-1, -1), 1, colors.grey)]))
            story.append(table)
            story.append(Spacer(1, 0.3 * inch))
            story.append(Paragraph("Detalles de Hallazgos por Equipo", h2_style))
            story.append(Spacer(1, 0.1 * inch))
            
            grouped_by_host = defaultdict(list)
            for result in self.scan_results: grouped_by_host[result['ip']].append(result)
            
            for host_ip in sorted(grouped_by_host.keys(), key=ipaddress.ip_address):
                story.append(Paragraph(f"<b>Equipo: {host_ip}</b>", styles['Normal']))
                host_vuln_data = [['Puerto', 'Servicio', 'Vulnerabilidad', 'Severidad', 'Tratamiento Propuesto']]
                vulnerabilities = sorted(grouped_by_host[host_ip], key=lambda x: list(SPANISH_SEVERITY.keys()).index(x['severity']) if x['severity'] in SPANISH_SEVERITY else 99)
                for vuln in vulnerabilities:
                    recommendation_text = vuln.get('recommendation', 'N/A').replace('\n', '<br/>')
                    row_data = [vuln['port'], vuln['service'], vuln['vulnerability'], SPANISH_SEVERITY.get(vuln['severity'], vuln['severity']), Paragraph(recommendation_text, styles['BodyText'])]
                    host_vuln_data.append(row_data)
                
                host_table = Table(host_vuln_data, colWidths=[0.5*inch, 0.8*inch, 2.2*inch, 0.8*inch, 2.5*inch])
                host_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey), ('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('VALIGN', (0, 0), (-1, -1), 'TOP')]))
                story.append(host_table)
                story.append(Spacer(1, 0.2 * inch))
            
            doc.build(story)
            Clock.schedule_once(lambda dt: setattr(self, 'scan_status', f"Informe '{os.path.basename(report_path)}' generado."))
        except Exception as e:
            error_message = f"Error al generar PDF: {e}"
            Clock.schedule_once(lambda dt, exc=error_message: setattr(self, 'scan_status', f"[color=ff0000]{exc}[/color]"))

    def show_help_popup(self):
        help_content = """
[b]Guía de Uso de ScanIA[/b]

¡Bienvenido a ScanIA! Esta herramienta te permite realizar análisis de vulnerabilidades en rangos de direcciones IP utilizando el poder de Nmap y un modelo de IA para la clasificación de hallazgos.

[b]1. Panel de Configuración (Izquierda)[/b]

[b]• Rango de IP:[/b]
Introduce el rango de direcciones IP que deseas analizar. El campo se autocompleta con la IP de tu red local como punto de partida. Debes llenar los cuatro octetos tanto para la IP inicial como para la final.

[b]• Opciones de Escaneo:[/b]
Selecciona las técnicas de escaneo que Nmap utilizará. Las opciones más comunes ya vienen activadas.
  [i]- Escaneo SYN (-sS):[/i] Rápido y sigiloso. Requiere privilegios de administrador.
  [i]- Escaneo TCP Connect (-sT):[/i] Más lento y ruidoso, pero no necesita privilegios especiales.
  [i]- Escaneo UDP (-sU):[/i] Analiza puertos UDP, puede ser muy lento.
  [i]- Detección de S.O. (-O):[/i] Intenta identificar el sistema operativo del equipo.
  [i]- Detección de Versión (-sV):[/i] Intenta determinar la versión de los servicios en ejecución. [b]Requerido[/b] para el análisis de Vulners.
  [i]- No hacer Ping (-Pn):[/i] Asume que el host está activo y escanea directamente. Útil si los equipos bloquean pings.
  [i]- Análisis Vulners:[/i] Utiliza el script de Vulners para buscar vulnerabilidades conocidas (CVEs) asociadas a las versiones de los servicios detectados.

[b]• Argumentos Adicionales:[/b]
Campo para usuarios avanzados. Aquí puedes añadir cualquier otro argumento de Nmap que desees, como por ejemplo [i]-T4[/i] para un escaneo más rápido o [i]--top-ports 20[/i] para analizar solo los 20 puertos más comunes.

[b]• Botón INICIAR / DETENER ESCANEO:[/b]
Presiona [b]INICIAR ESCANEO[/b] para comenzar el análisis con la configuración seleccionada. Mientras el escaneo está en progreso, el botón cambiará a [b]DETENER ESCANEO[/b], permitiéndote cancelarlo en cualquier momento.

[b]2. Panel de Resultados (Derecha)[/b]

Una vez finalizado el escaneo, los resultados aparecerán aquí.
[b]• Resumen General:[/b] En la parte superior verás un gráfico y estadísticas sobre los hallazgos, clasificados por severidad (Crítica, Alta, Media, Baja).
[b]• Hallazgos por Equipo:[/b] Cada equipo analizado tendrá su propia tarjeta. Puedes hacer clic en el botón [b]+[/b] o [b]-[/b] para expandir o contraer la lista de vulnerabilidades encontradas en ese equipo.

[b]3. Barra Superior e Inferior[/b]

[b]• Exportar:[/b] Permite guardar el informe completo de los resultados en un archivo PDF.
[b]• Barra de Progreso:[/b] La barra inferior te muestra el progreso general del escaneo, el estado actual (ej: "Escaneando: 192.168.1.5") y el estado del motor de IA.

[b]Uso Responsable:[/b] Utiliza esta herramienta de forma ética y solo en redes para las cuales tengas autorización explícita para analizar.
"""
        popup = HelpPopup(help_text=help_content)
        popup.open()
    
    # --- MÉTODO AÑADIDO ---
    def show_about_popup(self):
        about_content = """
[size=20sp][b]ScanIA[/b][/size]
[i]Herramienta para el Análisis de Vulnerabilidades con IA[/i]

Este software es el resultado de un Trabajo Fin de Estudios presentado para el Máster Universitario en Ciberseguridad.

[b]Autor:[/b] Dairo José Ortega Fonseca
[b]Institución:[/b] Escuela Superior de Ingeniería y Tecnología - Universidad Internacional de La Rioja (UNIR)
[b]Fecha del Trabajo:[/b] 21 de Abril de 2025

[b]Resumen del Proyecto[/b]
[size=13sp]El propósito de este proyecto es el diseño y desarrollo de ScanIA, una herramienta para el análisis automatizado de vulnerabilidades en redes locales, apoyada en inteligencia artificial y tecnologías de código abierto. La solución integra funcionalidades como escaneo de servicios, clasificación automática de riesgos y generación de informes técnicos. ScanIA se distingue por su facilidad de uso y su enfoque accesible para entornos con recursos limitados. Se presenta como una alternativa viable y eficiente para fortalecer la seguridad de redes internas en organizaciones pequeñas o educativas.[/size]

[b]Tecnologías Utilizadas[/b]
[size=13sp]• [b]Lenguaje:[/b] Python 3.11
• [b]Escáner de Red:[/b] Nmap 7.94
• [b]Machine Learning:[/b] Scikit-learn (Random Forest y SVM)
• [b]Interfaz Gráfica:[/b] Kivy 2.3.0[/size]

[b]Contribución Principal[/b]
[size=13sp]La propuesta de ScanIA se distingue por ofrecer una integración completa de escaneo automatizado, clasificación inteligente, una interfaz de usuario amigable y generación de informes detallados, todo en una solución práctica y accesible para personal no especializado.[/size]
"""
        popup = AboutPopup(about_text=about_content)
        popup.open()