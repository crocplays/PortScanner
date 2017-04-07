from  scapy.all import *

def isUDP(p):
    return UDP in p

def isICMP(p):
    return ICMP in p

def UDPScan(ip,PortList):
    """gets a target ip and port list and returns open ports """
    dstip= ip
    openPorts = list()
    for i in PortList:
        pack = sr1(IP(dst=dstip)/UDP(dport=i),timeout=5)
        if pack is not None:
            
            if pack[0].haslayer(UDP):
                print "port "+ str(i) + " is open"
                openPorts.append(i)
            elif pack[0].haslayer(ICMP):
                print "port "+ str(i) + " is closed/filtered"
        else:
            print "port "+ str(i) + " is open/filtered"
    return openPorts


targetIP = input("please enter target ip: ")
portsToScan = (10,80,443)
#portsToScan= input("enter the ports you wish to scan: ")
#portsToScan = portsToScan.split(',')
UDPScan(targetIP,portsToScan) 
        


