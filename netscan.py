from scapy.all import ARP, Ether, srp

def netScan():
    # IP Address
    targetIP = "173.225.242.0/24"
    
    # ARP Packet
    arp = ARP(pdst=targetIP)
    
    # Broadcast Packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # stack the ether and the arp
    packet = ether / arp
    
    # this will output a list of pairs in the format (sent_packet, received_packet)
    result = srp(packet, timeout=3)[0]
    
    clients = []
    for sent, received in result:
        clients.append({"ip": sent.psrc, 'mac': received.hwsrc})
    return clients

if __name__ == "__main__":
    print("AVAILABLE DEVICES ON THE NETWORK")
    #print("IP" + " "*18 + "MAC")
    clientList = netScan()
    for eachClient in clientList: 
        print(f"{eachClient['ip']} \t {eachClient['mac']}")
