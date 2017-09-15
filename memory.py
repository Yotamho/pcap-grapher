from logging import Logger

from flow import Flow


class Memory:
    def __init__(self):
        self.inner = {}
        self.logger = Logger(self.__class__.__name__)

    def upsert(self, pkt):
        four_tuple = packet_to_four_tuple(pkt)
        if four_tuple:
            if four_tuple in self.inner:
                self.update(four_tuple, pkt)
            else:
                self.insert(four_tuple, pkt)
        else:
            self.logger.warn("Non TCP/UDP Packet: " + pkt.number)

    def update(self, four_tuple, pkt):
        self.inner[four_tuple].ingest(pkt)

    def insert(self, four_tuple, pkt):
        self.inner[four_tuple] = Flow(pkt)

    def items(self):
        for four_tuple, flow in self.inner.items():
            yield four_tuple, flow

    def get_minimal_timestamp(self):
        return min([flow.start_time for flow in self.inner.values()])


def packet_to_four_tuple(pkt):
    if pkt.transport_layer:
        transport_layer = getattr(pkt, pkt.transport_layer.lower())
        return frozenset({(pkt.ip.src, transport_layer.srcport), (pkt.ip.dst, transport_layer.dstport)})
    else:
        return None
