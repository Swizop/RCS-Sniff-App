from asyncio.windows_events import NULL
import pyshark

def main():
    capture = pyshark.FileCapture('20210726-124925.cap')
    g = open("output.txt", 'w')
    eventsNr = 0
    oneSentUnresolved = False
    prev = NULL

    
    for pkt in capture:
        try:
            if pkt.ip.src == '10.0.0.1' and pkt.ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                    and pkt.ip.len == '327' and pkt.tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 is writing a message for Phone 2\n")
                oneSentUnresolved = False

            elif pkt.ip.dst == '10.0.0.1' and pkt.ip.src in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                    and pkt.ip.len == '848' and pkt.tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 is writing a message for Phone 1\n")
                oneSentUnresolved = False
            

            elif pkt.ip.src == '10.0.0.1' and pkt.ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                and int(pkt.ip.len) >= 250 and pkt.tcp.flags_push == '1' and (prev == NULL or prev.ip.len == '576'):
                nr = int(pkt.ip.len) - 250
                oneSentUnresolved = True
                expected = "2ACK"
            
            elif oneSentUnresolved == True and pkt.ip.dst == '10.0.0.1' and pkt.ip.src in ['216.239.36.128', '216.239.36.129','216.239.36.130']:
                if pkt.tcp.flags_push == '1' and pkt.ip.len == '347':
                    if expected == "2PUSH":
                        expected = "1ACK"
                    else:
                        oneSentUnresolved = False
                elif pkt.tcp.flags_ack == '1' and pkt.ip.len == '40':
                    if expected == "2ACK":
                        expected = "2PUSH"
                    else:
                        oneSentUnresolved = False
                else:
                    oneSentUnresolved = False

            elif oneSentUnresolved == True and pkt.ip.src == '10.0.0.1' and pkt.ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130']:
                if pkt.tcp.flags_ack == '1' and pkt.ip.len == '40':
                    if expected == "1ACK":
                        eventsNr += 1
                        g.write(f"Event {eventsNr}. Phone 1 sent a text message to Phone 2, which is {nr} characters long\n")
                oneSentUnresolved = False

            prev = pkt
    
        except AttributeError:
            continue

    capture.close()
    g.close()

if __name__ == '__main__':
    main()




#OLD VERSION

# import pyshark
# from collections import defaultdict

# def main():
#     with open("output.txt", 'w') as g:
#         d = defaultdict(int)
#         streamList = [0]             #each event is given a code. 
#                                 # 1 = intercepted phone is typing a message
#         ackList = []
#         streamsNr = 0
#         capture = pyshark.FileCapture('20210724-204615.cap', display_filter="tcp")

#         for pkt in capture:
#             try:
#                 # print(str(pkt.ip.src), str(pkt.tcp.field_names), sep=", ")
#                 # print(pkt.ip.len)
#                 if d[pkt.tcp.seq] == 0 and d[pkt.tcp.ack] == 0:             #new stream of events
#                     streamsNr += 1
#                     streamList.append(0)
#                     d[pkt.tcp.ack] = streamsNr
#                     if pkt.ip.src == '10.0.0.1' and (pkt.ip.dst ==  '216.239.36.128' or pkt.ip.dst ==  '216.239.36.129' or pkt.ip.dst ==  '216.239.36.130'):
#                         streamList[streamsNr] = 1

#                     d[pkt.tcp.seq] = -streamsNr
#                     d[pkt.tcp.ack] = streamsNr


#                 elif d[pkt.tcp.seq] > 0:
#                     if streamList[d[pkt.tcp.seq]] == 1 and pkt.ip.src == '10.0.0.1' and (pkt.ip.dst ==  '216.239.36.128' or pkt.ip.dst ==  '216.239.36.129' or pkt.ip.dst ==  '216.239.36.130') \
#                         and pkt.ip.len == '327' and pkt.tcp.flags_psh == '1':
#                         streamList[d[pkt.tcp.seq]] = 3
#                         g.write("Phone 1 is writing a text message intended for phone 2")

#                     # else:


#                     # if pkt.ip.len == '327':
#                     #     print(pkt.layers)
#             # d[pkt.tcp.ack] = 1
#             except AttributeError:
#                 continue

#         capture.close()
# if __name__ == '__main__':
#     main()