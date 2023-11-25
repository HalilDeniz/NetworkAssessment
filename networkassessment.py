#!/usr/bin/python
# -*- coding: utf-8 -*-

# creator   : Alperen Uğurlu
# updated by: Halil Deniz

import argparse
import time

from colorama import Fore, Style, init

from attack_detection import DnsTunnelingDetector, SshTunnelingDetector
from structure_module import PacketStructure, FileHandler

init(autoreset=True)


class NetworkCompromiseAssessment:
    def __init__(self, file_path, protocols, output_path, number_packet):
        self.file_handler = FileHandler()
        self.packet_structure = PacketStructure(file_path)
        self.suspicious_keywords = ["password", "login", "admin", "root", "bank", "credit", "card", "paypal", "malware",
                                    "virus", "trojan"]
        self.detectors = [DnsTunnelingDetector(self.suspicious_keywords),
                          SshTunnelingDetector(self.suspicious_keywords)]
        self.protocols = protocols
        self.output_path = output_path
        self.number_packet = number_packet

    def run(self):
        start_time = time.time()
        ip_addresses = self.packet_structure.get_all_ip_addresses()

        if self.number_packet:
            ip_addresses = sorted(list(ip_addresses))[:self.number_packet]

        for index, source_ip in enumerate(ip_addresses, start=1):
            print(f"\n{Fore.CYAN}[+] {index}: Checking IP address:{Style.RESET_ALL} {source_ip}")
            self.packet_structure.capture.reset()
            for packet in self.packet_structure.capture:
                if hasattr(packet, 'IP') and packet['IP'].src == source_ip and (
                        self.protocols is None or packet.transport_layer in self.protocols):
                    for detector in self.detectors:
                        if detector.detect(packet):
                            msg = f"[+] Detected {detector.__class__.__name__} from {source_ip}"
                            print(msg)
                            if self.output_path:
                                self.file_handler.save_to_file(msg, self.output_path)

        end_time = time.time()
        elapsed_time = end_time - start_time
        msg = f"Scanning completed in {elapsed_time:.2f} seconds"
        print(msg)
        if self.output_path:
            self.file_handler.save_to_file(msg, self.output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Compromise Assessment Tool")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the .pcap or .pcapng file")
    parser.add_argument("-p", "--protocols", nargs="+", type=str, choices=["TCP", "UDP", "DNS", "HTTP", "SMTP", "SMB"],
                        help="Specify protocols to scan (e.g., TCP UDP)")
    parser.add_argument("-o", "--output", type=str, help="Path to save the scan results (optional)")
    parser.add_argument("-n", "--number-packet", type=int, help="Number of packets to scan (optional)")

    try:
        args = parser.parse_args()
        assessment = NetworkCompromiseAssessment(args.file, args.protocols, args.output, args.number_packet)
        assessment.run()
    except Exception as e:
        print(f"Error executing the script: {e}")
