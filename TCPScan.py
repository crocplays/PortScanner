from scapy.all import *
#import logging

def isTCP(p):
    return TCP in p

def scan(ip,portList):
    """prints the status of a port. recieves ip,port """
    dstip=ip
    for dstport in portList:
        
        pack = sr1(IP(dst= dstip)/TCP(dport = dstport),timeout = 5)
        if pack is not None:
            
            if pack[0].haslayer(TCP):
                print " "
        
                if(pack[TCP].flags == 18) or (pack[TCP].flags == 16):
                    print "port " + str(dstport) +" is open"
                    openPorts.append(dstport)
                elif((pack[TCP].flags == 4) or (pack[TCP].flags == 20) ):
                    print "port "+ str(dstport) + " is closed"
        
            
            

global openPorts
openPorts = list()


targetIP = input("enter the target's ip address: ")
#there are 65535 ports in a computer
portList = (80,443)
scan(targetIP,portList)
    

print openPorts



