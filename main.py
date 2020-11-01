from scapy.all import *
import sys

ip_src_block = []
ip_dst_block = []
port_dst_block = []
port_src_block = []
protocol_to_block = []
def enter_credensials(thing, place_to_add):
    finish=False
    i=0
    x=""
    while not finish:
        print ("enter", thing, "number", i) 
        place_to_add.append(str(input()))
        print("do you want to add another one?")
        if (input() == 'n' or 'N'):
            finish = True 
        i+=1

def set_credensials():
    print ("enter packet_credensials\n")
    print("enter ip src to block:\n")
    enter_credensials("ip src to block", ip_src_block)
    print("enter ip dst to block:\n")
    enter_credensials("ip dst to block", ip_dst_block)
    print ("enter port src to block:\n")
    enter_credensials("port src to block", ip_src_block)
    print("enter port dst to block:\n")
    enter_credensials("port dst to block", port_dst_block)
    print ("enter protocols to lookup and block\n")
    enter_credensials("procol name to block", protocol_to_block)

    packet_credensials = {"ip_src": ip_src_block, "ip_dst": ip_dst_block, "port_src":port_src_block, "port_dst":port_dst_block, "protocl":protocls_to_block}
def check_credensials(packet):
    if (packet[IP].src in ip_src_block or packet[IP].dst in ip_dst_block):
        return False
    if (TCP in packet):
        if (packet[TCP].sport in port_src_block or packet[TCP].dport in port_dst_block):
            return False
    for protocol in protocol_to_block:
        if protocol in packet:
            return False
    return True 


def hundule(packet):
    if check_credensials(packet):
        sendp(packet)

#sniff(iface=conf.iface, prn=hundule, filter = "ip")

if __name__ == "__main__":
    set_credensials()
