#!/usr/bin/env python3
"""
Week 6: Final Working Version with Reliable Anomaly Detection
"""

import unittest
import tempfile
import os
import time
import random
import dpkt
import socket
from collections import deque
import numpy as np
import psutil
import logging
import sys
from io import BytesIO
from unittest.mock import patch, MagicMock

# --- Monitoring Components ---

class TrafficAnalyzer:
    """Improved traffic analysis with reliable anomaly detection"""
    def __init__(self, window_size=5, threshold=3.0):
        self.window_size = window_size
        self.threshold = threshold
        self.packet_counts = deque(maxlen=window_size)
        self.byte_counts = deque(maxlen=window_size)
        
    def update_stats(self, packet_sizes):
        """Update traffic statistics"""
        if packet_sizes:  # Only update if we have packets
            self.packet_counts.append(len(packet_sizes))
            self.byte_counts.append(sum(packet_sizes))
        
    def detect_anomalies(self):
        """Detect traffic anomalies using enhanced statistical methods"""
        if len(self.packet_counts) < self.window_size:
            return False
            
        # Calculate moving averages and standard deviations
        packet_mean = np.mean(self.packet_counts)
        packet_std = np.std(self.packet_counts)
        current_packets = self.packet_counts[-1]
        
        byte_mean = np.mean(self.byte_counts)
        byte_std = np.std(self.byte_counts)
        current_bytes = self.byte_counts[-1]
        
        # Calculate modified z-scores using median absolute deviation
        # More robust to outliers than standard z-score
        packet_median = np.median(self.packet_counts)
        packet_mad = np.median(np.abs(self.packet_counts - packet_median))
        packet_mzscore = 0.6745 * (current_packets - packet_median) / packet_mad if packet_mad > 0 else 0
        
        byte_median = np.median(self.byte_counts)
        byte_mad = np.median(np.abs(self.byte_counts - byte_median))
        byte_mzscore = 0.6745 * (current_bytes - byte_median) / byte_mad if byte_mad > 0 else 0
        
        # Consider both count and volume anomalies
        return (abs(packet_mzscore) > self.threshold or 
                abs(byte_mzscore) > self.threshold)

class ResourceMonitor:
    """Monitor system resources and adjust operations"""
    def __init__(self, max_cpu=70, max_mem=80):
        self.max_cpu = max_cpu
        self.max_mem = max_mem
        self.current_sampling_rate = 1.0
        
    def check_resources(self):
        """Check current system resource usage"""
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        return cpu, mem
        
    def adjust_sampling(self):
        """Adaptively adjust sampling rate based on resource usage"""
        cpu, mem = self.check_resources()
        
        if cpu > self.max_cpu or mem > self.max_mem:
            self.current_sampling_rate = max(0.1, self.current_sampling_rate * 0.8)
        elif cpu < self.max_cpu * 0.7 and mem < self.max_mem * 0.7:
            self.current_sampling_rate = min(1.0, self.current_sampling_rate * 1.1)
            
        return self.current_sampling_rate

class MockPacketCapture:
    """Mock packet capture for testing"""
    def __init__(self, interface):
        self.interface = interface
        self.packets = []
        
    def generate_test_packets(self, count=100):
        """Generate test packets"""
        self.packets = [random.randint(40, 1500) for _ in range(count)]
        return self.packets

# --- Test Cases ---

class TestTrafficAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = TrafficAnalyzer(window_size=5, threshold=3.0)
        
    def test_normal_traffic(self):
        """Test with normal traffic patterns"""
        # Consistent normal traffic
        for _ in range(10):
            self.analyzer.update_stats([random.randint(40, 1500) for _ in range(100)])
        self.assertFalse(self.analyzer.detect_anomalies())
        
    def test_attack_traffic(self):
        """Test with attack traffic patterns"""
        # Create normal baseline (5 data points)
        for _ in range(5):
            self.analyzer.update_stats([random.randint(40, 1500) for _ in range(100)])
        
        # Create sudden spike (attack traffic)
        # Make the spike significantly different in both count and size
        self.analyzer.update_stats([random.randint(40, 1500) for _ in range(20)] + [9000]*80)
        
        # Debug output to see what's happening
        print(f"\nDebug - Packet counts: {list(self.analyzer.packet_counts)}")
        print(f"Debug - Byte counts: {list(self.analyzer.byte_counts)}")
        
        # Should detect this as an anomaly
        self.assertTrue(self.analyzer.detect_anomalies(), 
                       "Failed to detect attack traffic pattern")

class TestResourceMonitor(unittest.TestCase):
    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    def test_resource_adaptation(self, mock_mem, mock_cpu):
        """Test adaptive sampling"""
        monitor = ResourceMonitor()
        
        # Simulate low usage
        mock_cpu.return_value = 30
        mock_mem.return_value = MagicMock(percent=40)
        self.assertAlmostEqual(monitor.adjust_sampling(), 1.0, delta=0.1)
        
        # Simulate high usage
        mock_cpu.return_value = 90
        mock_mem.return_value = MagicMock(percent=90)
        self.assertLess(monitor.adjust_sampling(), 1.0)

class TestMockCapture(unittest.TestCase):
    def test_packet_generation(self):
        """Test mock packet generation"""
        pc = MockPacketCapture('eth0')
        packets = pc.generate_test_packets(50)
        self.assertEqual(len(packets), 50)
        self.assertTrue(all(40 <= p <= 1500 for p in packets))

class PcapTests(unittest.TestCase):
    def test_pcap_analysis(self):
        """Test analysis of generated pcap data"""
        with tempfile.NamedTemporaryFile(suffix='.pcap') as tmpfile:
            # Create test pcap
            writer = dpkt.pcap.Writer(tmpfile)
            for _ in range(100):
                eth = dpkt.ethernet.Ethernet()
                eth.src = b'\x00\x11\x22\x33\x44\x55'
                eth.dst = b'\x66\x77\x88\x99\xaa\xbb'
                writer.writepkt(eth.pack())
            tmpfile.flush()
            
            # Analyze
            analyzer = TrafficAnalyzer()
            with open(tmpfile.name, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                sizes = [len(buf) for _, buf in pcap]
                analyzer.update_stats(sizes)
                self.assertGreater(analyzer.packet_counts[-1], 0)

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    
    # Run tests
    unittest.main(verbosity=2)