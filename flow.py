import pyshark.packet.packet
import config
from logging import Logger
from collections import Counter

from entity import Entity


class Flow:
    def __init__(self, pkt: pyshark.packet.packet.Packet):
        self.packets = []
        self.protocols = Counter()
        self.logger = Logger(self.__class__.__name__)

        is_packet_upstream = check_if_packet_is_upstream(pkt)
        if is_packet_upstream is not None:
            self.start_time = float(pkt.sniff_timestamp)
            self.end_time = float(pkt.sniff_timestamp)
            self.ingest(pkt)

            self.client = Entity(pkt, is_packet_upstream)
            self.server = Entity(pkt, not is_packet_upstream)
        else:
            self.logger.error("Packet does not include client configured IP. Packet number: " + pkt.number)

    def ingest(self, pkt):
        self.end_time = float(pkt.sniff_timestamp)
        self.packets.append(pkt)
        self.count_protocol(pkt)

    def count_protocol(self, pkt: pyshark.packet.packet.Packet):
        self.protocols[pkt.layers[3].layer_name] += 1

    def __len__(self):
        return len(self.packets)

    def __str__(self):
        return "\nFlow: " + str(self.client) + " -> " + str(self.server) + "\n\t" \
               + "Protocols: " + str(self.protocols) + "\n\t" \
               + "No. of packets: " + str(len(self))

def check_if_packet_is_upstream(pkt: pyshark.packet.packet.Packet):
    addresses = (pkt.ip.src, pkt.ip.dst)
    client_configured_ip = config.client_ip
    if client_configured_ip in addresses:
        return client_configured_ip == addresses[0]
    else:
        return None
