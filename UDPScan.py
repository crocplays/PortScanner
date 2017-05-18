from  scapy.all import *

def isUDP(p):
    """
    checks if the packet is a UDP packet"""
    return UDP in p

def isICMP(p):
    """ 
    checks if the packet is an ICMP packet"""
    return ICMP in p

def scan(dstip,PortList):
    """
    get a list of ports and scans them.
    the script creates a UDP packet and sends it to each port.
    if the return packet is an UDP packet then the ports is open.
    if the return packet is an ICMP packet then the port is closed or filtered.
    else the port is either open or filtered"""
    Ports = list()
    for i in PortList:
        pack = sr1(IP(dst=dstip)/UDP(dport=i),timeout=5)
        if pack is not None:
            if pack[0].haslayer(UDP):
                print "port "+ str(i) + " is open"
                Ports.append( "port "+ str(i) + " is open\r\n")
            elif pack[0].haslayer(ICMP):
                Ports.append( "port "+ str(i) + " is closed/filtered\r\n")
                print "port "+ str(i) + " is closed/filtered"
        else:
            Ports.append( "port "+ str(i) + " is open/filtered\r\n")
            print "port "+ str(i) + " is open/filtered"
    return Ports


#targetIP = input("please enter target ip: ")
#portsToScan = (10,80,443)
#portsToScan= input("enter the ports you wish to scan: ")
#portsToScan = portsToScan.split(',')
#UDPScan(targetIP,portsToScan) 
        


