from asyncio.windows_events import NULL
from pickle import FALSE, TRUE
from socket import timeout
import constants
import pyshark
import ipaddress
import sys
import requests
import matplotlib.pyplot as plt
from matplotlib.pyplot import figure

def capture_traffic():
    """Capture incoming and outgoing traffic"""
    capture = pyshark.LiveCapture(interface=network_interface)
    capture.sniff(timeout=timeout)
    packets = [pkt for pkt in capture._packets]
    capture.close()

    ip_list = []
    for packet in packets:
        try:
            src_addr = packet.ip.src
            dst_addr = packet.ip.dst
            if(ipaddress.ip_address(src_addr).is_global):
                ip_list.append(src_addr) if src_addr not in ip_list else ip_list
            elif (ipaddress.ip_address(dst_addr).is_global):
                ip_list.append(dst_addr) if dst_addr not in ip_list else ip_list
        except AttributeError as e:
            # ignore packets other than TCP, UDP and IPv4
            pass
    return ip_list

def geolocate_ip(ip, countries_list):
    """Geolocate IP adress using IPLeak API"""
    response = requests.get(constants.IP_LEAK_URL+ip)
    if(response.status_code==200 and response.text.find("error") ==-1):
        if response.json()[constants.COUNTRY_NAME] not in countries_list:
            countries_list[response.json()[constants.COUNTRY_NAME]] = 0
        countries_list[response.json()[constants.COUNTRY_NAME]] += 1

def create_bar_graph(countries_list):
    """Create a bar graph from captured and geolocated ip adresses"""
    probability = [*countries_list.values()]
    names = [*countries_list]
    plt.bar(names, probability)
    plt.xticks(names, rotation='vertical')
    plt.yticks(probability)
    plt.ylabel('Times connected')
    plt.savefig(constants.HISTOGRAM_FILE, bbox_inches='tight')


if __name__ == "__main__":
    if(len(sys.argv) != constants.NUM_OF_ARGS):
        print('There should be exactly {} arguments. Got {}'.format(constants.NUM_OF_ARGS, len(sys.argv)))
        exit()

    network_interface = sys.argv[1]
    timeout = int(sys.argv[2])

    ip_list = capture_traffic()

    countries_list = {}
    for ip in ip_list:
        geolocate_ip(ip, countries_list)

    create_bar_graph(countries_list)