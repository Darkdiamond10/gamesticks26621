import subprocess

# Definir el comando a ejecutar
comando = ['./kairo', '-c', 'config.json']

# Ejecutar el comando
try:
    resultado = subprocess.run(comando, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("Salida estándar:", resultado.stdout.decode())
    print("Error estándar:", resultado.stderr.decode())
except subprocess.CalledProcessError as e:
    print(f"Error al ejecutar el comando: {e}")
except FileNotFoundError:
    print("El archivo ./kairo no se encontró.")
