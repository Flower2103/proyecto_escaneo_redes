from flask import Flask, render_template, request, jsonify #crear la web, formularios y devolver json
import subprocess # ejecutar comandos arp y ping
import platform # detecta el sistema op para ajustar los comandos 
import threading # escaneo en seg plano sin bloquear la red
import socket # conexiones TCP y resolucion de nombres
from impacket.nmb import NetBIOS # obtener nombres netBIOS en la red
import time # pausas o tiempos de espera
from concurrent.futures import ThreadPoolExecutor #ejecutar multiples escenarios simultaneamente
import ipaddress #para que lea solo el rango

app = Flask(__name__)

hosts = {} # diccionario de host detectados
hosts_nuevos = {}
NETWORKS = "192.168.0.0/24" #ejmplo
LOCK = threading.Lock() #evita conflictos al modificar host desde multipleds hilos
progreso = 0
escaneando = False

OUI_DB = {}

#CARGAR BD DE FABRICANTES
def cargar_oui():
    global OUI_DB
    try:
        with open("oui.txt", "r", encoding="utf8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    prefijo = parts[0].replace("-", ":").upper()
                    fabricante = " ".join(parts[1:])
                    OUI_DB[prefijo] = fabricante
        print("OUI cargado:", len(OUI_DB), "fabricantes")
    except:
        print("No se pudo cargar oui.txt")


# DEVUELVE EL FABRICANTE A PARTIR DE LA MAC
def obtener_fabricante(mac):
    if mac in (None, "?", ""):
        return "Desconocido"
    mac = mac.upper().replace("-", ":")
    prefijo = ":".join(mac.split(":")[0:3])
    return OUI_DB.get(prefijo, "Desconocido")

# -------------------- PING --------------------
#EJECUTA UN PING PARA VERIFICAR SI EL HOST RESPONDE, AJUSTA SEGUN EL SO
def ping(ip):
    so = platform.system().lower()
    if so == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]  # 1s timeout
    else:
        cmd = ["ping", "-c", "1", "-W", "2", ip] # 2s timeout
    try:
        subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

# -------------------- MAC --------------------
# USA EL COMANDO ARP PARA OBTENER LA MAC DE LA IP
def get_mac(ip):
    try:
        arp = subprocess.check_output(["arp", "-a", ip]).decode(errors="ignore")
        for line in arp.split("\n"):
            if ip in line:
                parts = line.split()
                for p in parts:
                    if "-" in p or ":" in p:
                        return p
    except:
        pass
    return "?"

# -------------------- HOSTNAME --------------------
#INTENTA CON DNS, SI NO NETBIOS EN LAN, SI NO ?
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        pass
    try:
        bios = NetBIOS()
        names = bios.queryIPForName(ip, timeout=1)
        if names:
            return names[0]
    except:
        pass
    return "?"

# -------------------- SERVICIOS --------------------
#ESCANEA LOS PUERTOS COMUNES PARA DETECTAR LOS SERVICIOS
def scan_services(ip, ports=[80, 443, 22, 21, 3389]):
    """Escanea puertos comunes y devuelve los servicios abiertos"""
    abiertos = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5) # timeout aumentado
        try:
            if s.connect_ex((ip, port)) == 0:
                if port == 80:
                    abiertos.append("HTTP")
                elif port == 443:
                    abiertos.append("HTTPS")
                elif port == 22:
                    abiertos.append("SSH")
                elif port == 21:
                    abiertos.append("FTP")
                elif port == 3389:
                    abiertos.append("RDP")
                else:
                    abiertos.append(f"Port {port}")
        except:
            pass
        finally:
            s.close()
    return ", ".join(abiertos) if abiertos else "-"

# -------------------- ESCANEO DE IP --------------------
# COMBINA LAS FUNCIONES ANTERIORES, DEVULVE IN DICCIONARIO CON TODA LA INFO
def scan_ip(ip):
    if ping(ip):
        mac_addr = get_mac(ip)
        return {
            "ip": ip,
            "hostname": get_hostname(ip),
            "mac": mac_addr,
            "fabricante": obtener_fabricante(mac_addr),
            "services": scan_services(ip),
            "status": "active",
            "miss_count": 0
        }
    return None

# -------------------- ESCANEO COMPLETO EN SEGUNDO PLANO --------------------
# ESCANEA TODA LA RED USANDO HILO (ThreadPoolExecutor) para velocidad
# Mantiene hosts nuevos y actualiza hosts inactivos
# Controla progreso y variable escaneando

def full_scan_background(network):
    global hosts, hosts_nuevos, progreso, escaneando
    escaneando = True
    progreso = 0
    hosts_nuevos = {}

    #aqui se cambio
    # generar todas las IP válidas de la red (sin network/broadcast)
    net = ipaddress.ip_network(network, strict=False)
    ips = [str(ip) for ip in net.hosts()]

    total = len(ips)
    detectadas = set()

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ips}

        for i, future in enumerate(futures):
            result = future.result()
            ip = futures[future]

            with LOCK:
                if result:
                    detectadas.add(ip)
                    if ip not in hosts:
                        hosts_nuevos[ip] = result
                    hosts[ip] = result
                    print(f"Detectado: {ip} - {result['services']}")  # Debug

                progreso = int((i + 1) / total * 100)

    # ------------------ PROCESO DE IPs QUE NO RESPONDIERON ------------------
    with LOCK:
        for ip in list(hosts.keys()):
            if ip not in detectadas:
                if hosts[ip]["status"] == "active":
                    hosts[ip]["status"] = "inactive"  # solo aparece 1 vez
                else:
                    del hosts[ip]  # desaparece en siguiente escaneo

    escaneando = False

# -------------------- FLASK ROUTES --------------------
# Bloquea el acceso concurrente a hosts usando LOCK para evitar conflictos 
# con hilos que puedan modificarlo mientras se lee
@app.route("/")
def index():
    with LOCK:
        ordered = dict(sorted(hosts.items(), key=lambda x: list(map(int, x[0].split(".")))))
    return render_template(
        "index.html",
        networks=NETWORKS,
        hosts=ordered,
        progreso=progreso,
        escaneando=escaneando
    )

# Toma la red que envía el formulario web (request.form.get("networks"))
# Crea un hilo que ejecuta full_scan_background(NETWORKS)
# Esto permite que el escaneo se ejecute en segundo plano
@app.route("/iniciar_escaneo", methods=["POST"])
def iniciar_escaneo():
    global NETWORKS
    NETWORKS = request.form.get("networks", NETWORKS)
    hilo = threading.Thread(target=full_scan_background, args=(NETWORKS,))
    hilo.start()
    return jsonify({"status": "ok"})

@app.route("/progreso")
def obtener_progreso():
    global hosts_nuevos
    with LOCK:
        nuevos = hosts_nuevos.copy()
        hosts_nuevos = {}
    return jsonify({
        "progreso": progreso,
        "escaneando": escaneando,
        "nuevos": nuevos
    })

# -------------------- INICIO --------------------
if __name__ == "__main__":
    cargar_oui()
    print("Servidor iniciado en http://127.0.0.1:5000")
    app.run(debug=True)
