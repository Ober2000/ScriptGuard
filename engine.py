import re

def analyze_command(command):
   
    #Puntuación de riesgos y patrones
    risk_score = 0
    detected_patterns = []

    parts = [part.strip() for part in command.split('|')]
    
    #Detección en curl

    if "curl" in command.lower():
        detected_patterns.append("Comando curl detectado")
        urls = re.findall(r'https?://\S+', command)
        for url in urls:
            detected_patterns.append(f"URL detectada: {url}")

            #simulación de DB de dominios peligrosos
            suspicious_domains = ['pastebin.com', 'githubusercontent.com', 'gist.github.com']
            for domain in suspicious_domains:
                if domain in url:
                    risk_score    +=2
                    detected_patterns.append(f"Dominio potencialmente peligroso: {domain}")

            #flags sospechosas
            if "--insecure" in command or "-k" in command.split():
                risk_score +=3
                detected_patterns.append("Uso de curl con verificación SSL deshabilitada (--insecure)")

    #Detección bash
    if "bash" in command.lower() or "sh" in command.lower():
        detected_patterns.append("Comando bash/sh detectado")
        risk_score +=1
    
    # Detección de eval
    if "eval" in command:
        risk_score += 5
        detected_patterns.append("Uso de eval detectado")
    # Detección de descarga y ejecución directa (pipe curl a bash)
    if len(parts) > 1 and "curl" in parts[0].lower() and any(shell in parts[1].lower() for shell in ["bash", "sh"]):
        risk_score += 8
        detected_patterns.append("PELIGROSO: Descarga y ejecución directa (curl | bash)")
    
    # Detección de descargas a archivos y posterior ejecución
    if "curl" in command.lower() and ("-o " in command or "--output " in command) and "bash" in command.lower():
        risk_score += 6
        detected_patterns.append("PELIGROSO: Descarga a archivo y ejecución posterior")
    
    # Determinar el nivel de riesgo basado en la puntuación
    if risk_score >= 8:
        result = "malicious - riesgo alto"
    elif risk_score >= 4:
        result = "suspicious - precaución recomendada"
    else:
        result = "safe"
    
    return result, risk_score, detected_patterns

# Testing 
if __name__ == "__main__":
    print("Analizador de comandos curl/bash - Versión 2")
    print("Ingresa 'salir' para terminar\n")
    
    while True:
        command = input("\nIngresa un comando o escribe salir: ")
        if command.lower() == 'salir':
            break
            
        result, score, patterns = analyze_command(command)
        
        print(f"\nComando ingresado: {command}")
        print(f"Resultado: {result}")
        print(f"Puntuación de riesgo: {score}")
        
        if patterns:
            print("\nPatrones detectados:")
            for pattern in patterns:
                print(f"- {pattern}")
