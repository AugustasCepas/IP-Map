from pickle import FALSE, TRUE
from socket import timeout
import pyshark
import ipaddress

ipList = []

# define interface
networkInterface = "Ethernet"

# define capture object
capture = pyshark.LiveCapture(interface=networkInterface)
capture.sniff(timeout=2)
packets = [pkt for pkt in capture._packets]
capture.close()

print(capture)
for packet in packets:
    try:
        src_addr = packet.ip.src            # source address
        dst_addr = packet.ip.dst            # destination addres
        if(ipaddress.ip_address(src_addr).is_global):
            # print ("IP %s <-> %s" % (src_addr, dst_addr))
            # print("IP: ", src_addr)
            ipList.append(src_addr) if src_addr not in ipList else ipList
        elif (ipaddress.ip_address(dst_addr).is_global):
            # print("IP: ", dst_addr)
            ipList.append(dst_addr) if dst_addr not in ipList else ipList
    except AttributeError as e:
        # ignore packets other than TCP, UDP and IPv4
        pass

for ip in ipList:
    print(ip)

# print("listening on %s" % networkInterface)

# for packet in capture.sniff_continuously(packet_count=100):    
#     try:     
#         # get packet content
#         protocol = packet.transport_layer   # protocol type
#         src_addr = packet.ip.src            # source address
#         src_port = packet[protocol].srcport   # source port
#         dst_addr = packet.ip.dst            # destination address
#         dst_port = packet[protocol].dstport   # destination port

#         # output packet info
#         # print ("IP %s <-> %s (%s)" % (src_addr, dst_addr, protocol))
#         if(ipaddress.ip_address(src_addr).is_global):
#             # print("IP: ", src_addr)
#             ipList.append(src_addr) if src_addr not in ipList else ipList
#         elif (ipaddress.ip_address(dst_addr).is_global):
#             # print("IP: ", dst_addr)
#             ipList.append(dst_addr) if dst_addr not in ipList else ipList
#     except AttributeError as e:
#         # ignore packets other than TCP, UDP and IPv4
#         pass