# Network-Packet-Analyzer

Use pip install -r req.txt for installing all the required libarries of python.

This code captures network packets using the scapy library and performs various attacks detection on each packet. The code also writes the detected attack information to a csv file. The attacks detected include SYN Flood attack, Null Scan, FIN Scan, XMAS Scan, ACK Scan, UDP Scan, DNS Amplification Attack, ICMP Amplification Attack, ARP Spoofing, and DHCP Starvation Attack. The code uses various flags, layer properties and lengths of packets to determine the type of attack.

![image](https://user-images.githubusercontent.com/81178088/217606477-4d3a4c47-d723-4f72-9e5f-6187ee2def87.png)

It will display an alert, similar to this.

A csv file will also be created for further analysis.

iface is the interface you will be using to monitor and you can remove count for real time monitoring of all the packets.
