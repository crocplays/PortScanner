from scapy.all import *
#import logging

def isTCP(p):
    """ 
    checks if the the packet is a TCP packet"""
    return TCP in p

def scan(dstip,portList):
    """
    gets a list of ports and scans all of them and returns the status of each one.
    to scan the script creates a TCP packet and listens for the return packet.
    if the 'ack' flag is turned on or the 'ack' and 'syn' means the port is open.
    if the 'fin' flag is turned on or the 'fin' and 'ack' means the port is closed."""
    
    Ports = list()
    for dstport in portList:
        
        pack = sr1(IP(dst= dstip)/TCP(dport = dstport),timeout = 5)
        if pack is not None:
            
            if pack[0].haslayer(TCP):
                print " "
        
                if(pack[TCP].flags == 18) or (pack[TCP].flags == 16):
                    
                    print "port " + str(dstport) +" is open"
                    Ports.append("port "+str(dstport)+" is open\r\n")
                elif((pack[TCP].flags == 4) or (pack[TCP].flags == 20) ):
                    Ports.append("port "+str(dstport)+" is closed\r\n")
                    print "port "+ str(dstport) + " is closed"
    return Ports    
            
            





#targetIP = input("enter the target's ip address: ")
#there are 65535 ports in a computer
#portList = (40,80,443)
#print scan(targetIP,portList)
    









