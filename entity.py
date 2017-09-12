class Entity:
    def __init__(self, pkt, is_upstream):
        if is_upstream:
            self.ip = pkt.ip.src
            self.port = getattr(pkt, pkt.transport_layer.lower()).srcport
        else:
            self.ip = pkt.ip.dst
            self.port = getattr(pkt, pkt.transport_layer.lower()).dstport

    def __str__(self):
        return self.ip + ":" + str(self.port)
