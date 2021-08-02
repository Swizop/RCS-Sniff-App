from asyncio.windows_events import NULL
from re import T
import pyshark

def main():
    c = pyshark.FileCapture('229r10r24r7r8r.cap', \
        display_filter="(((ip.src == 216.239.36.128 || ip.src == 216.239.36.130 || ip.src == 216.239.36.129 || ip.src == 10.0.0.1)\
             && (ip.dst == 10.0.0.1 || ip.dst == 216.239.36.129 || ip.dst == 216.239.36.128 || ip.dst == 216.239.36.130))\
                  || ip.dst == 216.239.36.147 || ip.dst == 142.250.0.0/16 || ip.dst == 216.58.0.0/16 || ip.dst ==  193.231.252.1\
                    ) && !icmp")
    capture = list(c)
    c.close()
    g = open("output.txt", 'w')
    eventsNr = 0
    oneSentUnresolved = False
    dnsIndex = 0
    S1 = "10.0.0.1"
    S2 = ['216.239.36.128', '216.239.36.129','216.239.36.130']
    S3 = '216.239.36.147'
    googleDNS = 'maps.googleapis.com'
    lh3DNS = 'lh3.googleusercontent.com'
    lh5DNS = 'lh5.googleusercontent.com'
    dstDNS = '193.231.252.1'
    mediaDNS = 'rcs-user-content-eu.storage.googleapis.com'
    twoSentList = ["2PUSH", "1PUSH", "2ACK", "1ACK", "1PUSH", "2ACK", "2PUSH", "1ACK"]
    twoLocationList = ["2PUSH", "1ACK", "2PUSH", "1ACK", "1PUSH", "2ACK"]
    prev = NULL
    secondMultimediaUnresolved = False

    i = 0
    while i < len(capture):
        try:
            if capture[i].ip.dst == '10.0.0.1' and capture[i].ip.src in S2 \
                    and (capture[i].ip.len == '1398') and capture[i].tcp.flags_push == '1':
                if capture[i + 5].ip.dst == S3 or capture[i + 6].ip.dst == '216.239.36.147' or capture[i + 4].ip.dst == S3\
                    or (capture[i + 5].ip.dst == dstDNS and capture[i + 5].dns.qry_name == mediaDNS):
                    eventsNr += 1
                    g.write(f"Event {eventsNr}. Phone 2 sent a multimedia message to Phone 1\n")
                    i = i + 6
                    secondMultimediaUnresolved = True
                    while i < len(capture) and capture[i].ip.dst in [S3, mediaDNS]:
                        i += 1
                    oneSentUnresolved = False


            if capture[i].ip.src in S2 and capture[i].tcp.flags_push == '1':
                j = i + 1
                b = True
                r = 6
                for k in range(1, r):
                    if j >= len(capture):
                        b = False
                        break
                    if twoLocationList[k][0] == '1' \
                        and not(capture[j].ip.src == '10.0.0.1' and capture[j].ip.dst in S2):
                        if k == 1:              #sometimes the expected second packet is skipped
                            continue
                        b = False
                        break
                    if twoLocationList[k][0] == '2' \
                        and not(capture[j].ip.dst == '10.0.0.1' and capture[j].ip.src in S2):
                        b = False
                        break
                    if capture[j].tcp.flags_push != '1' and twoLocationList[k][1:] == 'PUSH':
                        b = False 
                        break
                    if capture[j].tcp.flags_ack != '1' and twoLocationList[k][1:] == 'ACK':
                        b = False
                        break
                    j += 1

                if b == True:
                    try:
                        if capture[j].dns.qry_name != googleDNS:
                            b = False
                    except AttributeError:
                        if capture[j].ip.dst[:7] != '142.250' and capture[j].ip.dst[:6] != '216.58':
                            b = False

                    if b == True:
                        eventsNr += 1
                        g.write(f"Event {eventsNr}. Phone 2 sent its location to Phone 1\n")
                        secondMultimediaUnresolved = False
                        while b == True:
                            if capture[j].ip.dst in S2 and capture[j + 1].ip.dst in S2 and capture[j + 1].tcp.flags_push == '1'\
                                 and capture[j + 2].ip.src in S2 \
                                 and capture[j + 3].ip.src in S2 and capture[j + 3].tcp.flags_push == '1'\
                                      and capture[j + 4].ip.dst in S2:
                                b = False
                                i = j + 5
                                if i >= len(capture):
                                    return
                            j += 1


            if capture[i].ip.src == '10.0.0.1' and capture[i].ip.dst in S2 \
                    and capture[i].ip.len == '327' and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 is writing a message for Phone 2\n")
                oneSentUnresolved = False
                secondMultimediaUnresolved = False

            elif capture[i].ip.dst == '10.0.0.1' and capture[i].ip.src in S2 \
                    and capture[i].ip.len == '848' and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 is writing a message for Phone 1\n")
                oneSentUnresolved = False
                secondMultimediaUnresolved = False

            
            elif capture[i].ip.src == '10.0.0.1' and capture[i].ip.dst in S2 \
                and capture[i].ip.len == '491' and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 has seen a message from Phone 2\n")
                oneSentUnresolved = False
                secondMultimediaUnresolved = False

            elif capture[i].ip.dst == '10.0.0.1' and capture[i].ip.src in S2 \
                and capture[i].ip.len == '977' and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 has seen a message from Phone 1\n")
                oneSentUnresolved = False 
                secondMultimediaUnresolved = False
            

            elif capture[i].ip.dst == '10.0.0.1' and capture[i].ip.src in S2 \
                and int(capture[i].ip.len) >= 754 and capture[i].tcp.flags_push == '1':
                nr = int(capture[i].ip.len) - 753
                j = i + 1
                b = True
                r = 8
                for k in range(1, r):
                    if j >= len(capture):
                        b = False
                        break
                    if twoSentList[k][0] == '1' \
                        and not(capture[j].ip.src == '10.0.0.1' and capture[j].ip.dst in S2):
                        b = False
                        break
                    if twoSentList[k][0] == '2' \
                        and not(capture[j].ip.dst == '10.0.0.1' and capture[j].ip.src in S2):
                        b = False
                        break
                    if capture[j].tcp.flags_push != '1' and twoSentList[k][1:] == 'PUSH':
                        b = False 
                        break
                    if capture[j].tcp.flags_ack != '1' and twoSentList[k][1:] == 'ACK':
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


            elif capture[i].ip.src == '10.0.0.1' and capture[i].ip.dst in S2 \
                and int(capture[i].ip.len) >= 250 and capture[i].tcp.flags_push == '1' and (prev == NULL or prev.ip.len == '576'):
                nr = int(capture[i].ip.len) - 250
                oneSentUnresolved = True
                expected = "2ACK"
            
            elif oneSentUnresolved == True and capture[i].ip.dst == '10.0.0.1' and capture[i].ip.src in S2:
                if capture[i].tcp.flags_push == '1' and capture[i].ip.len == '347':
                    if expected == "2PUSH":
                        expected = "1ACK"
                    else:
                        oneSentUnresolved = False
                elif capture[i].tcp.flags_ack == '1' and capture[i].ip.len == '40':
                    if expected == "2ACK":
                        expected = "2PUSH"
                    else:
                        oneSentUnresolved = False
                else:
                    oneSentUnresolved = False

            elif oneSentUnresolved == True and capture[i].ip.src == '10.0.0.1' and capture[i].ip.dst in S2:
                if capture[i].tcp.flags_ack == '1' and capture[i].ip.len == '40':
                    if expected == "1ACK":
                        eventsNr += 1
                        g.write(f"Event {eventsNr}. Phone 1 sent a text message to Phone 2, which is {nr} characters long\n")
                oneSentUnresolved = False
                secondMultimediaUnresolved = False

            elif capture[i].ip.dst == '216.239.36.147' and secondMultimediaUnresolved == False:
                oneSentUnresolved = False
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 sent a multimedia message to Phone 2\n")
                while i < len(capture):
                    if capture[i].ip.dst == '216.239.36.147' and capture[i].tcp.flags_fin == '1':
                        break
                    i += 1
                i += 1
                while i < len(capture):
                    if capture[i].ip.dst == '216.239.36.147' and capture[i].tcp.flags_ack == '1':
                        break
                    i += 1
            elif capture[i].ip.dst == '216.239.36.147':
                oneSentUnresolved = False

            
            elif capture[i].ip.dst == dstDNS:
                if capture[i].dns.qry_name in [googleDNS, lh3DNS, lh5DNS]:
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
