import pyshark
from logger import Logger

class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.logger = Logger()

    def analyze_packets(self):
        """
        Analyze all packets from the given PCAP file.
        """
        self.logger.log("##################### PACKET ANALYSIS #############################")
        self.logger.log(f"Analyzing packets from {self.pcap_file}...")

        try:
            cap = pyshark.FileCapture(self.pcap_file)
            packet_count = 0
            res = []

            for packet in cap:
                # Extract basic packet info
                try:
                    src_ip = packet.ip.src if hasattr(packet, 'ip') else "Unknown"
                    dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "Unknown"
                    protocol = packet.highest_layer
                    length = packet.length

                    result = f"Packet {packet_count+1}: {src_ip} → {dst_ip} | Protocol: {protocol} | Length: {length}"
                    self.logger.log(result)
                    res.append(result)

                except AttributeError:
                    result = f"Packet {packet_count+1}: Could not extract full details."
                    self.logger.log(result)
                    res.append(result)

                packet_count += 1

            cap.close()
            self.logger.log(f"Packet analysis completed. Total packets analyzed: {packet_count}")

        except Exception as e:
            self.logger.log(f"Error analyzing packets: {e}")

        return res
