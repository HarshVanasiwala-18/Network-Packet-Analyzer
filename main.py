import scapy.all as scapy
import pandas as pd
import signal
import datetime

with open(r'F:/Python Projects\Network Packet Analyzer\packet_details.csv', 'w') as file:
    file.write('Source, Source Port, Destination, Destination Port, Protocol, File Size, IP Address Layer, Time, Possible Attack')
    file.write('\n')

syn_count = {}

def syn_flood_detector(packet):
    global syn_count
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
    else:
        src_ip = packet.src
    if src_ip in syn_count:
        syn_count[src_ip] += 1
        if syn_count[src_ip] > 100:
            print(f"[ALERT] SYN Flood attack detected from {packet.summary()}")
            syn_count[src_ip] = 0
            return True
    else:
        syn_count[src_ip] = 1
    return False

def detect_null_scan(packet):
    if packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].flags == 0:
            if packet[scapy.TCP].sport != 0 or packet[scapy.TCP].dport != 0:
                print(f"[ALERT] Null Scan attack detected from {packet.summary()}")
                return True
    return False

def fin_scan(packet):
    if packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].flags == 0x01:
            if packet[scapy.TCP].sport != 0 or packet[scapy.TCP].dport != 0:
                print(f"[ALERT] FIN Scan attack detected from {packet.summary()}")
                return True
    return False

def xmas_scan(packet):
    if packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].flags == 0x29:
            if packet[scapy.TCP].sport != 0 or packet[scapy.TCP].dport != 0:
                print(f"[ALERT] XMAS Scan attack detected from {packet.summary()}")
                return True
    return False

def ack_scan(packet):
    if packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].flags == 0x10:
            if packet[scapy.TCP].sport == 0 or packet[scapy.TCP].dport == 0:
                print(f"[ALERT] ACK Scan attack detected from {packet.summary()}")
                return True
    return False

def udp_scan(packet):
    if packet.haslayer(scapy.UDP):
        if packet[scapy.UDP].dport == 0:
            print(f"[ALERT] UDP Scan detected from {packet.summary()}")
            return True
    return False

def dns_amplification_attack(packet):
    if packet.haslayer(scapy.DNS):
        if packet[scapy.DNS].qr == 0:
            if len(packet[scapy.DNS].qd) > 0:

                print(f"[ALERT] DNS Amplification Attack detected from {packet.summary()}")
                return True
    return False

def icmp_amplification_attack(packet):
    if packet.haslayer(scapy.ICMP):
        if packet[scapy.ICMP].type == 8:
            if packet[scapy.IP].len > 28:
                print(f"[ALERT] ICMP Amplification Attack detected from {packet.summary()}")
                return True
    return False

def arp_spoofer(packet):
    if packet.haslayer(scapy.ARP):
        if packet[scapy.ARP].op == 2:
            if packet[scapy.ARP].hwsrc != packet[scapy.ARP].hwdst:
                print(f"[ALERT] ARP Spoofing Attack detected from {packet.summary()}")
                return True
    return False

def dhcp_starvation_attack(packet):
    if packet.haslayer(scapy.DHCP):
        if packet[scapy.BOOTP].op == 1:
            print(f"[ALERT] DHCP Starvation Attack detected from {packet.summary()}")
            return True
    return False

def capture_packets(packets): 
    time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  
    for packet in packets:
        
        SF = syn_flood_detector(packet) 
        NS = detect_null_scan(packet)
        FS = fin_scan(packet)
        XS = xmas_scan(packet)
        AS = ack_scan(packet)
        UF = udp_scan(packet)
        DA = dns_amplification_attack(packet)
        IA = icmp_amplification_attack(packet)
        AR = arp_spoofer(packet)
        DS = dhcp_starvation_attack(packet)

        attack = {'SYN Flood': SF, 'Null Scan': NS, 'FIN Scan': FS, 'XMAS Scan': XS, 'ACK Scan': AS, 'UDP Scan': UF, 'DNS Amplification Attack': DA, 'ICMP Amplification Attack': IA, 'ARP Spoofing Attack': AR, 'DHCP Starvation Attack': DS}

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
        else:
            src_port = 'NA'
            dst_port = 'NA'

        if scapy.IP in packet:
            packet_info = [packet[scapy.IP].src, src_port, packet[scapy.IP].dst, dst_port, packet[scapy.IP].proto, len(packet), 'IP Layer',  time, attack]
        else:
            try:
                packet_info = [packet.src, src_port, packet.dst, dst_port, packet.porto, len(packet), 'Ethernet Layer', time, attack]
            except AttributeError:
                try:
                    packet_info = [packet.src, src_port, packet.dst, dst_port,'NA', len(packet), 'Ethernet Layer', time, attack]
                except:
                    packet_info = ['None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None']
        
    with open(r'F:/Python Projects\Network Packet Analyzer\packet_details.csv', 'a') as file:
        file.write(str(packet_info[0]) + ',' + str(packet_info[1]) + ',' + str(packet_info[2]) + ',' + str(packet_info[3]) + ',' + str(packet_info[4]) + ',' + str(packet_info[5]) + ',' + str(packet_info[6]) + ',' + str(packet_info[7] + ',' + str(packet_info[8])))
        file.write('\n')  

def keyboard_interrupt_handler():
    print('Keyboard Interrupt detected. Exiting the program')
    with open(r'F:\Python Projects\Network Packet Analyzer\packet_details.csv', 'r') as file:
        pandas_data = pd.read_csv(file)
        print(pandas_data)    
    exit(0)

if __name__ == '__main__':
    # count = number of packets to capture
    # iface = interface to capture packets from
    signal.signal(signal.SIGINT, keyboard_interrupt_handler)
    scapy.sniff(iface='WiFi 2', prn = capture_packets, count = 100)
        
    
    
    
    
