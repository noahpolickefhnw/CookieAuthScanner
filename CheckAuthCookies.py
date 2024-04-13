import requests
import sys
import subprocess
import ipaddress

#Parse NMAP output
def parse_nmap_output(output):
    open_ports = []
    lines = output.split('\n')
    for line in lines:
        if "/tcp" in line and "open" in line:
            port = line.split('/')[0]
            open_ports.append(port)
    return open_ports

#Parse Dirb output
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


#Split IPs in IP-Range
def split_ip_range(ip_range):
    start_ip, end_ip = ip_range.split('-')
    start_ip_parts = start_ip.split('.')
    end_ip_parts = end_ip.split('.')
    
    ips = []
    for i in range(int(start_ip_parts[-1]), int(end_ip_parts[-1]) + 1):
        ip = ".".join(start_ip_parts[:-1] + [str(i)])
        ips.append(ipaddress.IPv4Address(ip))
    
    return ips

#Scan IP and Portrange with NMAP
def scan_ip_range(ip_range, port_range="80,443"):
    if '-' in ip_range:
        ips = split_ip_range(ip_range)
    else:
        ips = [ip_range]
    
    for ip in ips:
        command = ["nmap", "-p", port_range, str(ip)]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
            if "Host seems down" in output:
                print("Die IP-Adresse oder das Netzwerk ist nicht erreichbar:", ip)
            else:
                print("Ein oder mehrere offene Ports gefunden in der IP:", ip)
                print(output)
                print('\n --------------------------------------------------------------- \n')
                open_ports = parse_nmap_output(output)
                for port in open_ports:
                    if port == "80":
                        url = f"http://{ip}"
                        find_admin_pages(url)
                        print('\n --------------------------------------------------------------- \n')

                    elif port == "443":
                        url = f"https://{ip}"
                        find_admin_pages(url)
                        print('\n --------------------------------------------------------------- \n')
                  
                    else:
                        url = f"https://{ip}:{port}"
                        find_admin_pages(url)
                        print('\n --------------------------------------------------------------- \n')
        except subprocess.CalledProcessError as e:
            print("Fehler bei der Ausführung von Nmap:", e)



#search for admin/login pages
def find_admin_pages(url):
    command = ["dirb", url, "./dirb/adminpages.txt"]
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if "FOUND: 0" in output:
            print("Es wurden keine Unterseiten gefunden für: ", url)
            check_set_cookie(url)
            check_authentication_methods(url)  
        else:
            admin_pages = parse_dirb_output(output)
            print(admin_pages)
            for admin_page in admin_pages:
                print("Folgende Seiten wurden gefunden: ", admin_page)
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
            print("Es wurden keine XSS Vulnabilities gefunden für: ", url)

        else:
            print("Es wurden folgende XSS Vulnabilities gefunden für: ", url) 
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

        if "login" in response.text:
            print("Formularbasierte Authentifizierung gefunden")
        else:
            print("Keine formularbasierte Authentifizierung gefunden")

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




        # Auf redirects prüfen
        if response.history:
            print("Redirects wurden gefunden")
            for resp in response.history:
                print("Umleitung zu:", resp.url)
        else:
            print("Keine Redirects gefunden")


    except requests.RequestException as e:
        print(f"Fehler beim Abrufen der Seite: {e}")



if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Verwendung: python CheckAuthCookies.py [StartIP-EndIP/FQDN] [Port-Range/Ports (Kommagetrennt)]")
        print("Beispiel: python CheckAuthCookies.py example.com 443,8443")
        print("Beispiel: python CheckAuthCookies.py 192.168.100.1-5 443-8443")
        sys.exit(1)
    
    ip_range = sys.argv[1]
    port_range = sys.argv[2] if len(sys.argv) == 3 else "80,443"
    scan_ip_range(ip_range, port_range)