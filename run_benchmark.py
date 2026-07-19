#!/usr/bin/env python3
import struct
import random
import time
import subprocess
import os

class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = 1700000000
        
    def write_global_header(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)
        
    def write_packet(self, data):
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)
        
    def close(self):
        self.file.close()

def create_ethernet_header(src_mac, dst_mac, ethertype=0x0800):
    return bytes.fromhex(dst_mac.replace(':', '')) + \
           bytes.fromhex(src_mac.replace(':', '')) + \
           struct.pack('>H', ethertype)

def create_ip_header(src_ip, dst_ip, protocol, payload_len):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000
    ttl = 64
    checksum = 0
    header = struct.pack('>BBHHHBBH', version_ihl, tos, total_len, ident, flags_frag, ttl, protocol, checksum)
    header += bytes([int(x) for x in src_ip.split('.')])
    header += bytes([int(x) for x in dst_ip.split('.')])
    return header

def create_tcp_header(src_port, dst_port, seq, ack, flags, payload_len=0):
    data_offset = 5 << 4
    window = 65535
    checksum = 0
    urgent = 0
    return struct.pack('>HHIIBBHHH', src_port, dst_port, seq, ack, data_offset, flags, window, checksum, urgent)

def create_udp_header(src_port, dst_port, payload_len):
    return struct.pack('>HHHH', src_port, dst_port, 8 + payload_len, 0)

def create_tls_client_hello(sni):
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    extensions_data = struct.pack('>H', len(sni_ext)) + sni_ext
    client_version = struct.pack('>H', 0x0303)
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)
    cipher_suites = struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302)
    compression = struct.pack('BB', 1, 0)
    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
    handshake = struct.pack('B', 0x01) + struct.pack('>I', len(client_hello_body))[1:] + client_hello_body
    record = struct.pack('B', 0x16) + struct.pack('>H', 0x0301) + struct.pack('>H', len(handshake)) + handshake
    return record

def create_dns_query(domain):
    txid = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode()
    question += struct.pack('B', 0)
    question += struct.pack('>HH', 1, 1)
    return txid + flags + counts + question

def generate_large_pcap(filename, num_flows=10000):
    print(f"Generating large PCAP '{filename}' with {num_flows} flows (~50,000 packets)...")
    writer = PCAPWriter(filename)
    user_mac = '00:11:22:33:44:55'
    gateway_mac = 'aa:bb:cc:dd:ee:ff'
    user_ip = '192.168.1.100'
    
    tls_domains = [
        ('142.250.185.206', 'www.google.com'),
        ('142.250.185.110', 'www.youtube.com'),
        ('157.240.1.35', 'www.facebook.com'),
        ('157.240.1.174', 'www.instagram.com'),
        ('104.244.42.65', 'twitter.com'),
        ('52.94.236.248', 'www.amazon.com'),
        ('23.52.167.61', 'www.netflix.com'),
        ('140.82.114.4', 'github.com'),
        ('104.16.85.20', 'discord.com'),
        ('35.186.224.25', 'zoom.us'),
        ('35.186.227.140', 'web.telegram.org'),
        ('99.86.0.100', 'www.tiktok.com'),
        ('35.186.224.47', 'open.spotify.com'),
        ('192.0.78.24', 'www.cloudflare.com'),
        ('13.107.42.14', 'www.microsoft.com'),
        ('17.253.144.10', 'www.apple.com')
    ]
    
    dns_domains = [
        'www.google.com', 'www.youtube.com', 'www.facebook.com', 'api.twitter.com',
        'netflix.com', 'microsoft.com', 'github.com', 'apple.com'
    ]
    
    for i in range(num_flows):
        # 80% TCP TLS, 20% UDP DNS
        if random.random() < 0.8:
            dst_ip, domain = random.choice(tls_domains)
            src_port = random.randint(49152, 65535)
            dst_port = 443
            seq = random.randint(1000, 100000)
            
            # TCP SYN
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq, 0, 0x02)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            
            # TCP SYN-ACK
            eth = create_ethernet_header(gateway_mac, user_mac)
            tcp = create_tcp_header(dst_port, src_port, seq + 100, seq + 1, 0x12)
            ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            
            # TCP ACK
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq + 1, seq + 101, 0x10)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            
            # TLS Client Hello
            tls_payload = create_tls_client_hello(domain)
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq + 1, seq + 101, 0x18, len(tls_payload))
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_payload))
            writer.write_packet(eth + ip + tcp + tls_payload)
            
            # TCP FIN-ACK
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq + 1 + len(tls_payload), seq + 101, 0x11)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
        else:
            domain = random.choice(dns_domains)
            src_port = random.randint(49152, 65535)
            dst_port = 53
            dns_payload = create_dns_query(domain)
            
            # DNS Query (UDP)
            eth = create_ethernet_header(user_mac, gateway_mac)
            udp = create_udp_header(src_port, dst_port, len(dns_payload))
            ip = create_ip_header(user_ip, '8.8.8.8', 17, len(udp) + len(dns_payload))
            writer.write_packet(eth + ip + udp + dns_payload)
            
    writer.close()
    print("PCAP file generated successfully.")

def run_engine(main_class, input_pcap, output_pcap):
    cmd = ['java', '-cp', 'target/classes', f'packetanalyzer.{main_class}', input_pcap, output_pcap]
    start = time.perf_counter()
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    end = time.perf_counter()
    if result.returncode != 0:
        print(f"Error running {main_class}: {result.stderr}")
        return None
    return (end - start) * 1000.0

def main():
    os.chdir('java')
    # Compile
    print("Compiling Java sources...")
    subprocess.run(['javac', '-d', 'target/classes', 'src/main/java/packetanalyzer/*.java'], check=True)
    
    pcap_file = '../benchmark_large.pcap'
    generate_large_pcap(pcap_file, num_flows=10000)
    
    # Run Single-threaded
    print("Benchmarking Single-threaded Engine (MainSimple)...")
    simple_time = run_engine('MainSimple', pcap_file, 'output_simple_bench.pcap')
    
    # Run Multi-threaded
    print("Benchmarking Multi-threaded Engine (MainDpi)...")
    multi_time = run_engine('MainDpi', pcap_file, 'output_multi_bench.pcap')
    
    if simple_time and multi_time:
        total_packets = 42000
        # Let's count actual packets
        import struct
        if os.path.exists(pcap_file):
            with open(pcap_file, 'rb') as f:
                f.seek(24) # Skip global header
                count = 0
                while True:
                    header = f.read(16)
                    if not header or len(header) < 16:
                        break
                    _, _, incl_len, _ = struct.unpack('<IIII', header)
                    f.seek(incl_len, 1)
                    count += 1
            total_packets = count

    # Cleanup bench outputs
    if os.path.exists('output_simple_bench.pcap'):
        os.remove('output_simple_bench.pcap')
    if os.path.exists('output_multi_bench.pcap'):
        os.remove('output_multi_bench.pcap')
    if os.path.exists(pcap_file):
        os.remove(pcap_file)
        
        simple_throughput = total_packets / (simple_time / 1000.0)
        multi_throughput = total_packets / (multi_time / 1000.0)
        speedup = simple_throughput / simple_throughput # Default if multi is slower, but let's calculate:
        speedup = multi_throughput / simple_throughput
        
        print("\n" + "="*50)
        print("                 BENCHMARK REPORT                 ")
        print("="*50)
        print(f"Total Packets Processed: {total_packets:,}")
        print(f"Single-threaded Time:    {simple_time:.2f} ms ({simple_throughput:,.2f} packets/sec)")
        print(f"Multi-threaded Time:     {multi_time:.2f} ms ({multi_throughput:,.2f} packets/sec)")
        print("-" * 50)
        print(f"Throughput Speedup:      {speedup:.2f}x")
        print("="*50 + "\n")
        
        # Write results to a file for inclusion in README
        with open('../benchmark_results.txt', 'w') as bf:
            bf.write(f"Total Packets: {total_packets:,}\n")
            bf.write(f"Single-threaded Throughput: {simple_throughput:,.2f} packets/sec\n")
            bf.write(f"Multi-threaded Throughput: {multi_throughput:,.2f} packets/sec\n")
            bf.write(f"Speedup: {speedup:.2f}x\n")

if __name__ == '__main__':
    main()
