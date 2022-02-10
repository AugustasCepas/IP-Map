from pickle import FALSE, TRUE
import pyshark

# define interface
networkInterface = "Ethernet"

# define capture object
capture = pyshark.LiveCapture(interface=networkInterface)

print("listening on %s" % networkInterface)

ipList = []

def isIPValid(x):
    if(x.find("192.168") > -1) or (x.find("255.") > -1):
        return FALSE
    else:
        return TRUE

for packet in capture.sniff_continuously(packet_count=10):
    # adjusted output
    
    try:
        # get timestamp
     
        # get packet content
        protocol = packet.transport_layer   # protocol type
        src_addr = packet.ip.src            # source address
        src_port = packet[protocol].srcport   # source port
        dst_addr = packet.ip.dst            # destination address
        dst_port = packet[protocol].dstport   # destination port

        # output packet info
        print ("IP %s <-> %s (%s)" % (src_addr, dst_addr, protocol))

        if(isIPValid(src_addr)):
            print("IP: ", dst_addr)
            ipList.append(dst_addr) if dst_addr not in ipList else ipList
        elif (isIPValid(dst_addr)):
            print("IP: ", src_addr)
            ipList.append(src_addr) if src_addr not in ipList else ipList

        # if(src_addr.find("192.168") > -1) or (src_addr.find("255.") > -1):
        #     print("IP: ", dst_addr)
        #     ipList.append(dst_addr) if dst_addr not in ipList else ipList
        # else if:
        #      print("IP: ", src_addr)
        #      ipList.append(src_addr) if src_addr not in ipList else ipList

    except AttributeError as e:
        # ignore packets other than TCP, UDP and IPv4
        pass
    print (" ")

for ip in ipList:
    print(ip)