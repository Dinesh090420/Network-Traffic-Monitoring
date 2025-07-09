#!/usr/bin/env python3
"""
Network Traffic Analyzer for Your Wireshark Capture
- Specifically analyzes 'wireshark packets.pcapng'
- Provides detailed protocol breakdown
- Identifies top talkers
- Detects potential anomalies
"""

import dpkt
import socket
import os
import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt

def analyze_your_capture(file_path):
    """Analyze your specific Wireshark capture file"""
    
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        print("Please ensure the file exists and try again.")
        return
    
    print(f"\nAnalyzing your capture file: {file_path}")
    
    try:
        with open(file_path, 'rb') as f:
            pcap = dpkt.pcapng.Reader(f) if file_path.endswith('.pcapng') else dpkt.pcap.Reader(f)
            
            # Initialize statistics
            stats = {
                'total_packets': 0,
                'total_bytes': 0,
                'protocols': defaultdict(int),
                'sources': defaultdict(int),
                'destinations': defaultdict(int),
                'ports': defaultdict(int),
                'timestamps': [],
                'packet_sizes': []
            }
            
            # Process each packet
            for ts, buf in pcap:
                stats['total_packets'] += 1
                stats['total_bytes'] += len(buf)
                stats['timestamps'].append(ts)
                stats['packet_sizes'].append(len(buf))
                
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        stats['sources'][src_ip] += 1
                        stats['destinations'][dst_ip] += 1
                        
                        # Transport layer analysis
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            stats['protocols']['TCP'] += 1
                            stats['ports'][tcp.dport] += 1
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            stats['protocols']['UDP'] += 1
                            stats['ports'][udp.dport] += 1
                        elif isinstance(ip.data, dpkt.icmp.ICMP):
                            stats['protocols']['ICMP'] += 1
                        else:
                            stats['protocols']['Other-IP'] += 1
                    else:
                        stats['protocols']['Non-IP'] += 1
                except Exception as e:
                    stats['protocols']['Unknown'] += 1
            
            # Generate report
            generate_report(stats, file_path)
            
    except Exception as e:
        print(f"Error analyzing file: {str(e)}")

def generate_report(stats, file_path):
    """Generate a detailed report from the collected statistics"""
    
    # Calculate time duration
    duration = stats['timestamps'][-1] - stats['timestamps'][0] if stats['timestamps'] else 0
    
    # Calculate rates
    avg_pps = stats['total_packets'] / duration if duration > 0 else 0
    avg_bps = (stats['total_bytes'] * 8) / duration if duration > 0 else 0
    
    # Anomaly detection
    sizes = np.array(stats['packet_sizes'])
    mean_size = np.mean(sizes)
    std_size = np.std(sizes)
    size_threshold = mean_size + 3 * std_size
    large_packets = sizes[sizes > size_threshold]
    
    # Protocol percentages
    proto_percent = {k: v/stats['total_packets'] for k, v in stats['protocols'].items()}
    
    # Print report
    print("\n=== Detailed Traffic Analysis Report ===")
    print(f"File: {os.path.basename(file_path)}")
    print(f"Capture duration: {duration:.2f} seconds")
    print(f"Total packets: {stats['total_packets']:,}")
    print(f"Total data: {stats['total_bytes']/1024:.2f} KB")
    print(f"Average rate: {avg_pps:.2f} packets/sec, {avg_bps/1000:.2f} Kbps")
    
    print("\nProtocol Distribution:")
    for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
        print(f"{proto:8}: {count:6} packets ({proto_percent[proto]:.1%})")
    
    print("\nTop 5 Source IPs:")
    for ip, count in sorted(stats['sources'].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip:15}: {count:6} packets")
    
    print("\nTop 5 Destination IPs:")
    for ip, count in sorted(stats['destinations'].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip:15}: {count:6} packets")
    
    print("\nTop 5 Destination Ports:")
    for port, count in sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{port:5}: {count:6} packets")
    
    print(f"\nAnomaly Detection: Found {len(large_packets)} unusually large packets (> {size_threshold:.0f} bytes)")
    
    # Generate visualizations
    generate_visualizations(stats)

def generate_visualizations(stats):
    """Create visualizations of the traffic data"""
    plt.figure(figsize=(15, 10))
    
    # Packet Size Distribution
    plt.subplot(2, 2, 1)
    plt.hist(stats['packet_sizes'], bins=50, color='skyblue', edgecolor='black')
    plt.title('Packet Size Distribution')
    plt.xlabel('Bytes')
    plt.ylabel('Count')
    
    # Protocol Distribution
    plt.subplot(2, 2, 2)
    labels, values = zip(*sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True))
    plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
    plt.title('Protocol Distribution')
    
    # Traffic Over Time
    plt.subplot(2, 2, 3)
    relative_times = [t - stats['timestamps'][0] for t in stats['timestamps']]
    plt.scatter(relative_times, stats['packet_sizes'], alpha=0.5, s=10)
    plt.title('Packet Sizes Over Time')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packet Size (bytes)')
    
    # Top Source IPs
    plt.subplot(2, 2, 4)
    top_sources = sorted(stats['sources'].items(), key=lambda x: x[1], reverse=True)[:5]
    ips, counts = zip(*top_sources)
    plt.bar(ips, counts, color='lightgreen')
    plt.title('Top 5 Source IPs')
    plt.xticks(rotation=45)
    plt.ylabel('Packet Count')
    
    plt.tight_layout()
    plt.savefig('traffic_analysis_report.png', dpi=300, bbox_inches='tight')
    print("\nSaved comprehensive visualization to 'traffic_analysis_report.png'")

if __name__ == '__main__':
    # Specify your exact capture file path here
    capture_file = "/Users/garbhapudinesh/Desktop/OSPROJECT/wireshark packets.pcapng"
    
    # Alternatively, you can uncomment this to use command-line argument:
    # import sys
    # if len(sys.argv) > 1:
    #     capture_file = sys.argv[1]
    
    analyze_your_capture(capture_file)