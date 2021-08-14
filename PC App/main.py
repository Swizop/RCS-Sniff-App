from asyncio.windows_events import NULL
import pyshark
import json
from collections import defaultdict
import re

from pyshark.capture.capture import Capture

def main():
    network = open("network.json", 'r')
    arch = json.load(network)
    network.close()

    c = pyshark.FileCapture('Receive_traffic.cap', display_filter=arch["display"])
    capture = list(c)
    c.close()
    g = open("output.txt", 'w')
    eventsNr = 0
    pendingLocation = False
    prev = NULL
    secondMultimediaUnresolved = False
    coordinates = defaultdict(int)


    i = 0
    while i < len(capture):
        try:
            # l = str(capture[i][-1])
            # if re.search("HTTP", l):
            #     print(1)
            if capture[i].ip.src in arch["S2"] and capture[i].ip.len in arch["MM2len"] and capture[i].tcp.flags_push == '1':
                if capture[i + 5].ip.dst == arch["S3"] or capture[i + 6].ip.dst == arch["S3"] or capture[i + 4].ip.dst == arch["S3"]\
                    or (capture[i + 5].ip.dst == arch["dstDNS"] and capture[i + 5].dns.qry_name == arch["mediaDNS"])\
                    or (capture[i + 6].ip.dst == arch["dstDNS"] and capture[i + 6].dns.qry_name == arch["mediaDNS"]):
                    eventsNr += 1
                    g.write(f"Event {eventsNr}. Phone 2 sent a multimedia message to Phone 1\n")
                    i = i + 6
                    secondMultimediaUnresolved = True
                    while i < len(capture) and capture[i].ip.dst in [arch["S3"], arch["mediaDNS"]]:
                        i += 1

            
            if capture[i].ip.src in arch["S2"] and capture[i].ip.len == arch["locationLength"]:
                j = i + 1
                b = True
                for k in range(1, 10):
                    if j >= len(capture):
                        b = False
                        break
                    if arch["twoLocationList"][k][0] == '1' and not(capture[j].ip.dst in arch["S2"]):
                        if k == 9:              #sometimes the expected last packet is delayed by 1
                            if not(capture[j + 1].ip.dst in arch["S2"]):
                                b = False
                                break
                        else:
                            b = False
                            break
                    if arch["twoLocationList"][k][0] == '2' and not(capture[j].ip.src in arch["S2"]):
                        b = False
                        break
                    if capture[j].tcp.flags_push != '1' and arch["twoLocationList"][k][1:] == 'PUSH':
                        if k == 3:              #sometimes the expected 4th packet is skipped
                            continue
                        b = False 
                        break
                    if capture[j].tcp.flags_ack != '1' and arch["twoLocationList"][k][1:] == 'ACK':
                        b = False
                        break
                    if capture[j].ip.len == arch["W2len"] and capture[j].ip.src in arch["S2"]:      #there is a case in which the location algorithm
                                                                                                #interferes with the second "seen event" 
                        b = False
                        break
                    j += 1

                if b == True:
                    i = i + 9
                    pendingLocation = True

            
            if capture[i].ip.dst in arch["S2"] and capture[i].ip.len == arch["W1len"] and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 is writing a message for Phone 2\n")
                secondMultimediaUnresolved = False

            elif capture[i].ip.src in arch["S2"] and capture[i].ip.len == arch["W2len"] and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 is writing a message for Phone 1\n")
                secondMultimediaUnresolved = False

            
            elif capture[i].ip.dst in arch["S2"] and capture[i].ip.len == arch["S1len"] and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 has seen a message from Phone 2\n")
                secondMultimediaUnresolved = False

            elif capture[i].ip.src in arch["S2"] and capture[i].ip.len == arch["S2len"] and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 has seen a message from Phone 1\n")
                secondMultimediaUnresolved = False
            

            elif capture[i].ip.dst == arch["S1"] and capture[i].ip.src in arch["S2"] \
                and int(capture[i].ip.len) > arch["Sent2len"] and capture[i].tcp.flags_push == '1':
                nr = int(capture[i].ip.len) - arch["Sent2len"]
                j = i + 1
                b = True
                r = 8
                for k in range(1, r):
                    if j >= len(capture):
                        b = False
                        break
                    if arch["twoSentList"][k][0] == '1' and not(capture[j].ip.dst in arch["S2"]):
                        b = False
                        break
                    if arch["twoSentList"][k][0] == '2' and not(capture[j].ip.src in arch["S2"]):
                        b = False
                        break
                    if capture[j].tcp.flags_push != '1' and arch["twoSentList"][k][1:] == 'PUSH':
                        b = False 
                        break
                    if capture[j].tcp.flags_ack != '1' and arch["twoSentList"][k][1:] == 'ACK':
                        b = False
                        break
                    j += 1

                if b == False:
                    i = i + 1
                    continue
                else:
                    i = j - 1
                    eventsNr += 1
                    g.write(f"Event {eventsNr}. Phone 2 sent a text message to Phone 1, which is {nr} characters long\n")
                    secondMultimediaUnresolved = False


            elif capture[i].ip.dst in arch["S2"] and int(capture[i].ip.len) >= arch["Sent1len"] and capture[i].tcp.flags_push == '1' and\
                     (prev == NULL or prev.ip.len == arch["Prevlen"]):
                nr = int(capture[i].ip.len) - arch["Sent1len"]
                if capture[i + 1].ip.src in arch["S2"] and capture[i + 1].ip.len == arch["Acklen"]\
                    and capture[i + 2].ip.src in arch["S2"] and capture[i + 2].ip.len == arch["Pushlen"]\
                        and capture[i + 3].ip.dst in arch["S2"] and capture[i + 3].ip.len == arch["Acklen"]:
                    g.write(f"Event {eventsNr}. Phone 1 sent a text message to Phone 2, which is {nr} characters long\n")
                    secondMultimediaUnresolved = False
                    i = i + 3
    

            elif capture[i].ip.dst == arch["S3"] and secondMultimediaUnresolved == False:
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 sent a multimedia message to Phone 2\n")
                while i < len(capture):
                    if capture[i].ip.dst == arch["S3"] and capture[i].tcp.flags_fin == '1':
                        break
                    i += 1
                i += 1
                while i < len(capture):
                    if capture[i].ip.dst == arch["S3"] and capture[i].tcp.flags_ack == '1':
                        break
                    i += 1
            
            try:
                prev = capture[i]
            except IndexError:
                return
    
            i += 1
        except AttributeError:
            i += 1
            continue

    g.close()

if __name__ == '__main__':
    main()
