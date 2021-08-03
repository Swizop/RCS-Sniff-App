from asyncio.windows_events import NULL
from re import T
import pyshark
import json

def main():
    network = open("network.json", 'r')
    arch = json.load(network)
    network.close()

    c = pyshark.FileCapture('229r10r24r7r8r.cap', display_filter=arch["display"])
    capture = list(c)
    c.close()
    g = open("output.txt", 'w')
    eventsNr = 0
    oneSentUnresolved = False
    dnsIndex = 0
    prev = NULL
    secondMultimediaUnresolved = False

    i = 0
    while i < len(capture):
        try:
            if capture[i].ip.src in arch["S2"] and capture[i].ip.len in arch["MM2len"] and capture[i].tcp.flags_push == '1':
                if capture[i + 5].ip.dst == arch["S3"] or capture[i + 6].ip.dst == arch["S3"] or capture[i + 4].ip.dst == arch["S3"]\
                    or (capture[i + 5].ip.dst == arch["dstDNS"] and capture[i + 5].dns.qry_name == arch["mediaDNS"]):
                    eventsNr += 1
                    g.write(f"Event {eventsNr}. Phone 2 sent a multimedia message to Phone 1\n")
                    i = i + 6
                    secondMultimediaUnresolved = True
                    while i < len(capture) and capture[i].ip.dst in [arch["S3"], arch["mediaDNS"]]:
                        i += 1
                    oneSentUnresolved = False


            if capture[i].ip.src in arch["S2"] and capture[i].tcp.flags_push == '1':
                j = i + 1
                b = True
                r = 6
                for k in range(1, r):
                    if j >= len(capture):
                        b = False
                        break
                    if arch["twoLocationList"][k][0] == '1' and not(capture[j].ip.dst in arch["S2"]):
                        if k == 1:              #sometimes the expected second packet is skipped
                            continue
                        b = False
                        break
                    if arch["twoLocationList"][k][0] == '2' and not(capture[j].ip.src in arch["S2"]):
                        b = False
                        break
                    if capture[j].tcp.flags_push != '1' and arch["twoLocationList"][k][1:] == 'PUSH':
                        b = False 
                        break
                    if capture[j].tcp.flags_ack != '1' and arch["twoLocationList"][k][1:] == 'ACK':
                        b = False
                        break
                    j += 1

                if b == True:
                    try:
                        if capture[j].dns.qry_name != arch["googleDNS"]:
                            b = False
                    except AttributeError:
                        if capture[j].ip.dst[:7] != arch["S4_1"] and capture[j].ip.dst[:6] != arch["S4_2"]:
                            b = False

                    if b == True:
                        eventsNr += 1
                        g.write(f"Event {eventsNr}. Phone 2 sent its location to Phone 1\n")
                        secondMultimediaUnresolved = False
                        while b == True:
                            if capture[j].ip.dst in arch["S2"] and capture[j + 1].ip.dst in arch["S2"] and capture[j + 1].tcp.flags_push == '1'\
                                 and capture[j + 2].ip.src in arch["S2"] and capture[j + 3].ip.src in arch["S2"] and capture[j + 3].tcp.flags_push == '1'\
                                      and capture[j + 4].ip.dst in arch["S2"]:
                                b = False
                                i = j + 5
                                if i >= len(capture):
                                    return
                            j += 1


            if capture[i].ip.dst in arch["S2"] and capture[i].ip.len == arch["W1len"] and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 is writing a message for Phone 2\n")
                oneSentUnresolved = False
                secondMultimediaUnresolved = False

            elif capture[i].ip.src in arch["S2"] and capture[i].ip.len == arch["W2len"] and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 is writing a message for Phone 1\n")
                oneSentUnresolved = False
                secondMultimediaUnresolved = False

            
            elif capture[i].ip.dst in arch["S2"] and capture[i].ip.len == arch["S1len"] and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 has seen a message from Phone 2\n")
                oneSentUnresolved = False
                secondMultimediaUnresolved = False

            elif capture[i].ip.src in arch["S2"] and capture[i].ip.len == arch["S2len"] and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 has seen a message from Phone 1\n")
                oneSentUnresolved = False 
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


            elif capture[i].ip.src == arch["S1"] and capture[i].ip.dst in arch["S2"] \
                and int(capture[i].ip.len) >= arch["Sent1len"] and capture[i].tcp.flags_push == '1' and\
                     (prev == NULL or prev.ip.len == arch["Prevlen"]):
                nr = int(capture[i].ip.len) - arch["Sent1len"]
                oneSentUnresolved = True
                expected = "2ACK"
            
            elif oneSentUnresolved == True and capture[i].ip.dst == arch["S1"] and capture[i].ip.src in arch["S2"]:
                if capture[i].tcp.flags_push == '1' and capture[i].ip.len == arch["Pushlen"]:
                    if expected == "2PUSH":
                        expected = "1ACK"
                    else:
                        oneSentUnresolved = False
                elif capture[i].tcp.flags_ack == '1' and capture[i].ip.len == arch["Acklen"]:
                    if expected == "2ACK":
                        expected = "2PUSH"
                    else:
                        oneSentUnresolved = False
                else:
                    oneSentUnresolved = False

            elif oneSentUnresolved == True and capture[i].ip.src == arch["S1"] and capture[i].ip.dst in arch["S2"]:
                if capture[i].tcp.flags_ack == '1' and capture[i].ip.len == arch["Acklen"]:
                    if expected == "1ACK":
                        eventsNr += 1
                        g.write(f"Event {eventsNr}. Phone 1 sent a text message to Phone 2, which is {nr} characters long\n")
                oneSentUnresolved = False
                secondMultimediaUnresolved = False

            elif capture[i].ip.dst == arch["S3"] and secondMultimediaUnresolved == False:
                oneSentUnresolved = False
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
            elif capture[i].ip.dst == arch["S3"]:
                oneSentUnresolved = False

            
            elif capture[i].ip.dst == arch["dstDNS"]:
                if capture[i].dns.qry_name in [arch["googleDNS"], arch["lh3DNS"], arch["lh5DNS"]]:
                    if dnsIndex == 0:
                        dnsIndex = 1
                        eventsNr += 1
                        g.write(f"Event {eventsNr}. Phone 1 sent its location to Phone 2\n")
                    else:
                        dnsIndex -= 1           #there should be 2 DNS packets sent to the IP for the same request
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
