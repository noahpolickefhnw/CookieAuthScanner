import requests
import sys
import subprocess

#Hilfsfunktion fürs parsen der NMAP Antwort
def parse_nmap_output(output):
    open_ports = []
    lines = output.split('\n')
    for line in lines:
        if "/tcp" in line and "open" in line:
            port = line.split('/')[0]
            open_ports.append(port)
    return open_ports

def parse_dirb_output(output):
    admin_pages = []
    lines = output.split('\n')
    for line in lines:
        if "+ https://" in line:
            admin_page = line.split("+ https://")[1].split(" ")[0]
            admin_pages.append("https://" + admin_page)
        elif "+ http://" in line:
            admin_page = line.split("+ http://")[1].split(" ")[0]
            admin_pages.append("http://" + admin_page)
    return admin_pages



#Scan IP and Portrange with NMAP
def scan_ip_range(ip_range, port_range="80,443"):
    command = ["nmap", "-p", port_range, ip_range]
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if "Host seems down" in output:
            print("Die IP-Adresse oder das Netzwerk ist nicht erreichbar:", ip_range)

        else:
            print("Ein oder mehrere offene Ports gefunden in der IP-Range:", ip_range)
            print("Ausgabe von Nmap:")
            #print(output)
            open_ports = parse_nmap_output(output)
            for port in open_ports:
                if port == "80":
                    url = f"http://{ip_range}"
                    print("URL - NMAP: ", url)
                    find_admin_pages(url)
                    print('\n --------------------------------------------------------------- \n')

                elif port == "443":
                    url = f"https://{ip_range}"
                    print("URL - NMAP: ", url)
                    find_admin_pages(url)
                    print('\n --------------------------------------------------------------- \n')
                  
                else:
                    url = f"https://{ip_range}:{port}"
                    print("URL - NMAP: ", url)
                    find_admin_pages(url)
                    print('\n --------------------------------------------------------------- \n')
    except subprocess.CalledProcessError as e:
        print("Fehler bei der Ausführung von Nmap:", e)



#search for admin/login pages
def find_admin_pages(url):
    command = ["dirb", url, "./dirb/adminpages.txt"] ############################################korrigieren
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if "FOUND: 0" in output:
            print("URL - DIRB - no sites: ", url)
            check_set_cookie(url)
            check_authentication_methods(url)  
        else:
            admin_pages = parse_dirb_output(output)
            print(admin_pages)
            for admin_page in admin_pages:
                #admin_url = f"{url}/{admin_page}"
                print("URL - DIRB - Site Found: ", admin_page)
                find_xss_vuln(admin_page)
                check_set_cookie(admin_page)
                check_authentication_methods(admin_page)

            
    except subprocess.CalledProcessError as e:
        print("Fehler bei der Ausführung von DIRB:", e)


#check the adminpages for XSS Vulnabilities
def find_xss_vuln(url):

 
    command = ["python3", "./XSStrike/xsstrike.py" , "-u", url, "--data", "username=<script>alert('XSS');</script>&password=<script>alert('XSS');</script>"]
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if "FOUND: 0" in output:
            print("No XSS Vulnabilities found for: ", url)

        else:
            print("XSS Vulnabilities found for: ", url) 
            print(output)
            
    except subprocess.CalledProcessError as e:
        print("Fehler bei der Ausführung von XSStrike:", e)


#Check set-cookie
def check_set_cookie(url):
    try:
        response = requests.get(url)
        headers = response.headers
        
        if 'Set-Cookie' in headers:
            print("Der HTTP-Antwortheader enthält Set-Cookie.")
        #    print("Set-Cookie-Wert:", headers['Set-Cookie'])
        else:
            print("Der HTTP-Antwortheader enthält kein Set-Cookie.")
            
    except requests.exceptions.RequestException as e:
        print("Fehler beim Abrufen der Seite:", e)



# Check cookies
def check_authentication_methods(url):
    try:
        response = requests.get(url)

        cookies = response.cookies

        session_cookie_found = False
        for cookie in cookies:
            if "session" in cookie.name.lower() or "id" in cookie.name.lower():
                session_cookie_found = True
                break
        if session_cookie_found:
            print("Ein Cookie mit 'session' oder 'id' im Namen wurde gefunden: ")
            print(f"{cookie.name}: {cookie.value}")
        else:
            print("Keine Session Cookies gefunden")

        # Überprüfen, ob ein Authentifizierungs-Cookie vorhanden ist
        auth_cookie_found = False
        for cookie in cookies:
            if "auth" in cookie.name.lower():
                auth_cookie_found = True
                break
        if auth_cookie_found:
            print("Ein Cookie mit 'auth' im Namen wurde gefunden: ")
            print(f"{cookie.name}: {cookie.value}")
        else:
            print("Keine authentifizierungs Cookies gefunden")


        # Überprüfen, ob die Website einen Formular-Login verwendet
        if "login" in response.text:
            print("Formularbasierte Authentifizierung gefunden!")

        # Auf redirects prüfen
        if response.history:
            print("Die Webseite leitet nach dem Login um.")


    except requests.RequestException as e:
        print(f"Fehler beim Abrufen der Seite: {e}")



if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Verwendung: python script.py <StartIP-EndIP> [Port-Range]")
        sys.exit(1)
    
    ip_range = sys.argv[1]
    port_range = sys.argv[2] if len(sys.argv) == 3 else "80,443"
    scan_ip_range(ip_range, port_range)