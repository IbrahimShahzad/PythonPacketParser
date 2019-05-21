import socket
import pypacker.pypacker as pypacker
from pypacker.pypacker import Packet
from pypacker import ppcap
from pypacker import psocket
from pypacker.layer12 import arp, ethernet, ieee80211, prism
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import udp,tcp
from pypacker.layer567 import radius
#import dpkt
from pypacker import pcapng

#pcap_file = ppcap.Reader(filename="TEST_Radius.pcap")
#pcap_file = pcapng.Reader(filename="TEST_Radius.pcap")
pcap_file = ppcap.Reader(filename="TEST_Radius.pcap")
cnt = 1
for ts, buf in pcap_file:
    if(cnt==3):
        break
    print(cnt)
    cnt +=1
    eth = ethernet.Ethernet(buf)
    eth2 = ethernet.Ethernet(buf)
    print("Packet :%s " % eth2)
    u = udp.UDP
    if eth[u] is not None:
        print("(%s):%s:%s->(%s)%s:%s" % (eth.src_s,eth[ip.IP].src_s,eth[u].sport,
                eth.dst_s,eth[ip.IP].dst_s,eth[u].dport))
        if(eth[radius.Radius] is not None):
            print("RADIUS")
            print(eth[radius.Radius])
            bb = (str(eth[radius.Radius].body_bytes))
            bc = (str(eth[radius.Radius]._body_bytes))
 #           bb = bb.replace("\x","")
            bb = bb.replace("b'(","")
            bb = bb.replace(")","")
            bb = bb.split("\\x")
            #bb = (str(eth[radius.Radius].body_bytes).split(" "))
            print(bb)
            print(bc)
            lb= list(bb)
            
            #print(body_byte)
            #print(lb)
            #print(str(eth[radius.Radius].body_bytes))
            #print(int(lb[]))
            count=0;
#            for i in lb:
                #print("%d : %s" % count, lb[i])
#                print(count,lb[count])
#                count=count+1;
            print(type(eth[radius.Radius].body_bytes))
    print(20*"-")
pcap_file.close()



