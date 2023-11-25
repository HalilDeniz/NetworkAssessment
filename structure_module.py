import pyshark


class PacketStructure:
    def __init__(self, file_path):
        self.capture = pyshark.FileCapture(file_path, keep_packets=False)

    def get_all_ip_addresses(self):
        ip_addresses = set()
        for packet in self.capture:
            if hasattr(packet, 'IP'):
                ip_addresses.add(packet['IP'].src)
                ip_addresses.add(packet['IP'].dst)
        return ip_addresses


class FileHandler:
    @staticmethod
    def save_to_file(message, file_path):
        if file_path:
            with open(file_path, 'a') as f:
                f.write(message + "\n")
