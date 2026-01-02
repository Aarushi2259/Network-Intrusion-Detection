import pyshark
from datetime import datetime
from Feature_extraction.feature_extractor import FeatureExtractor
from config.feature_schema import FEATURE_COLUMNS
from Data_pipeline.CSVWriter import CSVfeatureWriter


class PacketSniffer:

    def start(self, packet_limit=1500):
        capture = pyshark.LiveCapture(interface='Wi-Fi')
        extractor = FeatureExtractor()
       
        prev_time = None

        for i, packet in enumerate(capture.sniff_continuously(packet_count=packet_limit)):
            try:
                timestamp = packet.sniff_time
                inter_arrival = (timestamp - prev_time).total_seconds() if prev_time else 0
                prev_time = timestamp

                record = {
                    "timestamp": timestamp,
                    "packet_length": int(packet.length),
                    "highest_layer": packet.highest_layer,
                    "transport_layer": packet.transport_layer,
                    "src_ip": packet.ip.src if hasattr(packet, 'ip') else None,
                    "dst_ip": packet.ip.dst if hasattr(packet, 'ip') else None,
                    "src_port": packet[packet.transport_layer].srcport if packet.transport_layer else None,
                    "dst_port": packet[packet.transport_layer].dstport if packet.transport_layer else None,
                    "tcp_flags": packet.tcp.flags if hasattr(packet, 'tcp') else None,
                    "window_size": packet.tcp.window_size if hasattr(packet, 'tcp') else None,
                    "ttl": packet.ip.ttl if hasattr(packet, 'ip') else None,
                    "inter_arrival_time": inter_arrival
                }

                # Send record to feature extractor
                features = extractor.extract(record)
                print(features)

            except Exception as e:
                print("Error:", e)
                continue


if __name__ == "__main__":
    PacketSniffer().start()
