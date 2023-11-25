from collections import defaultdict


class AttackDetector:
    def __init__(self, suspicious_keywords):
        self.suspicious_keywords = suspicious_keywords
        self.syn_counter = defaultdict(int)
        self.slowloris_counter = defaultdict(int)

    def detect(self, packet):
        raise NotImplementedError("Must be implemented by subclasses")

    def detect_suspicious_keywords(self, packet):
        return next(
            (
                (True, keyword)
                for keyword in self.suspicious_keywords
                if keyword in str(packet)
            ),
            (False, None),
        )


class DnsTunnelingDetector(AttackDetector):
    def detect(self, packet):
        if 'DNS' in packet and hasattr(packet['DNS'], 'qr') and packet['DNS'].qr == '0':
            for ans in packet['DNS'].answers:
                if 'type' in ans and ans.type == 'TXT' and len(ans.data) > 100:
                    return True
        return False


class SshTunnelingDetector(AttackDetector):
    def detect(self, packet):
        return hasattr(packet, 'SSH') and hasattr(packet, 'TCP') and (
                packet['TCP'].sport > 1024 or packet['TCP'].dport > 1024)
