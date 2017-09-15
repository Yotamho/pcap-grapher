import argparse

parser = argparse.ArgumentParser(description="Create an intuitive and interactive graph of a client's IP traffic")
parser.add_argument("pcap_path", metavar="<pcap path>", help="path to the pcap file")
parser.add_argument("client_ip", metavar="<client's ip>",
                    help="client's ip allow filtering and focusing on a specific IP")
parser.add_argument("-f", dest="display_filter", metavar="display-filter",
                    help="Wireshark display filter, additional to the client filter.")

args = parser.parse_args()
pcap_path = args.pcap_path
display_filter = args.display_filter
client_ip = args.client_ip
