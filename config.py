import argparse

parser = argparse.ArgumentParser(description="create schema to a PCAP")
parser.add_argument("pcap", metavar="p", help="path to pcap file")
parser.add_argument("client_ip", metavar="c", help="client's ip")
parser.add_argument("-f", dest="display_filter", metavar="f", help="display filter")

args = parser.parse_args()
pcap_path = args.pcap
display_filter = args.display_filter
client_ip = args.client_ip
