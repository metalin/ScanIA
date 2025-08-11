# generar_datos.py
import csv
import random

NUM_ROWS = 7000
OUTPUT_FILE = 'your_vulnerability_data_new.csv'

# --- Base de datos de vulnerabilidades con VECTORES DE ATAQUE ---
SCENARIOS = [
    {
        "service_name": "ssh", "port": 22,
        "versions": ["OpenSSH 5.3p1", "OpenSSH 7.2p2"],
        "vulns": [
            ("Critical", "Aplicar parches de seguridad inmediatamente.", "Versión antigua con RCE conocido (Vector: Ejecución Remota de Código)."),
            ("High", "Actualizar o restringir acceso por firewall.", "Versión desactualizada permite bypass de autenticación (Vector: Escalada de Privilegios)."),
            ("Low", "Aplicar recomendaciones de seguridad básicas.", "Permite enumeración de usuarios (Vector: Fuga de Información).")
        ]
    },
    {
        "service_name": "http", "port": 80,
        "versions": ["Apache httpd 2.2.15", "nginx 1.10.3"],
        "vulns": [
            ("High", "Actualizar o restringir acceso por firewall.", "Versión de Apache con múltiples fallos (Vector: Denegación de Servicio)."),
            ("Medium", "Revisar configuración del servicio.", "Mala configuración de directorios (Vector: Fuga de Información)."),
            ("Info", "Monitorear el servicio regularmente.", "Servidor web activo sin fallos evidentes.")
        ]
    },
    {
        "service_name": "ftp", "port": 21,
        "versions": ["vsftpd 2.3.4", "ProFTPD 1.3.5"],
        "vulns": [
            ("Critical", "Aplicar parches de seguridad inmediatamente.", "Backdoor conocido en la versión (Vector: Acceso no Autorizado Total)."),
            ("Medium", "Revisar configuración del servicio.", "Permite acceso anónimo con escritura (Vector: Modificación de Datos)."),
        ]
    },
    {
        "service_name": "microsoft-ds", "port": 445,
        "versions": ["Samba smbd 4.3.11", "Windows 7"],
        "vulns": [
            ("Critical", "Aplicar parches de seguridad inmediatamente.", "Vulnerable a EternalBlue (Vector: Ejecución Remota de Código, Wormable)."),
            ("High", "Actualizar o restringir acceso por firewall.", "Vulnerable a SambaCry (Vector: Ejecución Remota de Código)."),
        ]
    },
    {
        "service_name": "rtsp", "port": 554,
        "versions": ["Dahua DVR", "Hikvision Camera"],
        "vulns": [
            ("High", "Asegurar CCTV: Cambiar credenciales y actualizar firmware.", "Cámara con credenciales por defecto (Vector: Acceso no Autorizado)."),
            ("Critical", "Asegurar CCTV: Cambiar credenciales y actualizar firmware.", "Firmware con backdoor conocido (Vector: Acceso no Autorizado Total).")
        ]
    },
    {
        "service_name": "telnet", "port": 23,
        "versions": ["Linux Telnetd"],
        "vulns": [
            ("Critical", "Aplicar parches de seguridad inmediatamente.", "Servicio Telnet activo (Vector: Interceptación de Tráfico, MitM).")
        ]
    }
]

def generate_data():
    header = ['ip_address', 'port_number', 'service_name', 'product_version', 'vulners_output', 'vulnerability_context_description', 'manual_severity', 'proposed_treatment_solution']
    with open(OUTPUT_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        print(f"--- Generando {NUM_ROWS} filas de datos enriquecidos ---")
        for i in range(NUM_ROWS):
            scenario = random.choice(SCENARIOS)
            ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            port = scenario['port']
            service = scenario['service_name']
            version = random.choice(scenario['versions'])
            severity, treatment, context = random.choice(scenario['vulns'])
            vulners_sim = f"Simulated CVE for {service} ({severity})"
            
            writer.writerow([ip, port, service, version, vulners_sim, context, severity, treatment])
            if (i + 1) % 1000 == 0:
                print(f"  ... {i + 1} / {NUM_ROWS} filas generadas ...")
    print(f"\n✅ ¡Éxito! Se ha creado '{OUTPUT_FILE}'")

if __name__ == '__main__':
    generate_data()