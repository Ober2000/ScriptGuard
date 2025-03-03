import re
def analyze_command(command):
    parts = [part.strip() for part in command.split('|')]
    # Patrones específicos para cada comando
    curl_patterns = [
        r'curl.http://.',  # Cualquier curl que descargue de una URL
    ]
    bash_patterns = [
        r'bash',             # Simplemente detecta si hay un bash
    ]
    dangerous_patterns = [
        r'rm -rf',           # Patrones generales peligrosos
    ]
    # Analizar cada parte
    for part in parts:
        if any(re.search(pattern, part, re.IGNORECASE) for pattern in curl_patterns):
            print(f"Parte detectada como curl: {part}")
            if "http://shady.com" in part:  # Ejemplo simple
                return "malicious - URL sospechosa"
        
        #comando bash
        if any(re.search(pattern, part, re.IGNORECASE) for pattern in bash_patterns):
            print(f"Parte detectada como bash: {part}")
        # Checar patrones peligrosos en cualquier parte
        if any(re.search(pattern, part, re.IGNORECASE) for pattern in dangerous_patterns):
            return "malicious - comando peligroso"
    # Si hay un curl seguido de un bash, es sospechoso
    if len(parts) > 1 and "curl" in parts[0] and "bash" in parts[1]:
        return "malicious - descarga y ejecución directa"
    return "safe"

while True:
    command =  input("Ingresa un comando o 'salir' para terminar:")
    if command.lower() == 'salir':
        break
    print(f"Comando ingresado:: {command}")
