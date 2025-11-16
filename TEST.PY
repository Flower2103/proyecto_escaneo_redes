import subprocess

print("Ejecutando arp -a...\n")

try:
    salida = subprocess.check_output("arp -a", shell=True, text=True)
    print(salida)
except Exception as e:
    print("ERROR:", e)
