from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap

# 1. Normal TCP (Simulated HTTP Traffic)
pkt1 = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(b"GET / HTTP/1.1\r\n\r\n")

# 2. Normal UDP (Simulated DNS Query)
pkt2 = IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=43210, dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))

# 3. Normal ICMP (Ping)
pkt3 = IP(src="192.168.1.50", dst="10.0.0.1") / ICMP()

# 4. Anomalous TCP (Large payload simulating data exfiltration or buffer overflow)
pkt4 = IP(src="192.168.1.200", dst="192.168.1.50") / TCP(sport=4444, dport=22) / Raw(b"X" * 1200)

packets = [pkt1, pkt2, pkt3, pkt4]

# Export to a physical file
file_name = "test_traffic.pcap"
wrpcap(file_name, packets)
print(f"[+] {file_name} generated successfully with {len(packets)} packets.")