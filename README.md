# pcap-grapher
### Create an intuitive and interactive graph of a client's IP traffic. ###

Usage:
`pcap-schema.py [-h] [-f display-filter] <pcap path> <client's ip>`
![Alt text](example.png?raw=true "example-graph")

Additional features:
* Filter the traffic to get an even-more concise graph
* Touch a packet (circle) to get details about the flow (incl. protocols)

Prerequisites:
* pyshark
* numpy
* matplotlib

TODOs:
* Add linux support (PCAP path loading)