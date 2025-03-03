import re

def analyze_command(command):
    parts = [part.strip() for part in command.split('|')]
    
    # Buscar patrones básicos
    for part in parts:
        if "curl" in part.lower():
            print(f"Se detectó curl: {part}")
        if "bash" in part.lower():
            print(f"Se detectó bash: {part}")
    
    # Si hay curl seguido de bash, es sospechoso
    if len(parts) > 1 and "curl" in parts[0].lower() and "bash" in parts[1].lower():
        return "malicious - descarga y ejecución directa"
    
    return "safe"

# Testing 
while True:
    command = input("Ingresa un comando o 'salir' para terminar: ")
    if command.lower() == 'salir':
        break
    print(f"Comando ingresado: {command}")
    result = analyze_command(command)
    print(f"Resultado: {result}")
