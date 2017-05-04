from scapy.all import *
#import logging

def isTCP(p):
    return TCP in p

def scan(dstip,portList):
    """prints the status of a port. recieves ip,port """
    
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
    









