import pyshark

def main():
    capture = pyshark.FileCapture('20210726-124925.cap')
    g = open("output.txt", 'w')
    eventsNr = 0

    oneSentList = [0]                        #containers and variables used in the case of phone 1 sending a text message
    oneSentCharList = [0]
    oneSentUnresolved = 0
    
    for pkt in capture:
        try:
            if pkt.ip.src == '10.0.0.1' and pkt.ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                    and pkt.ip.len == '327' and pkt.tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 is writing a message for Phone 2\n")

            elif pkt.ip.dst == '10.0.0.1' and pkt.ip.src in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                    and pkt.ip.len == '848' and pkt.tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 is writing a message for Phone 1\n")
            

            elif pkt.ip.src == '10.0.0.1' and pkt.ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                and int(pkt.ip.len) >= 250 and pkt.tcp.flags_push == '1':
                oneSentCharList.append(int(pkt.ip.len) - 250)
                oneSentUnresolved += 1
                oneSentList.append("2ACK")
            
            elif oneSentUnresolved > 0 and pkt.ip.dst == '10.0.0.1' and pkt.ip.src in ['216.239.36.128', '216.239.36.129','216.239.36.130']:
                if pkt.tcp.flags_push == '1':
                    try:
                        i = oneSentList.index("2PUSH")
                        oneSentList[i] = "1ACK"
                    except ValueError:
                        pass
                elif pkt.tcp.flags_ack == '1':
                    try:
                        i = oneSentList.index("2ACK")
                        oneSentList[i] = "2PUSH"
                    except ValueError:
                        pass

            elif oneSentUnresolved > 0 and pkt.ip.src == '10.0.0.1' and pkt.ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130']:
                if pkt.tcp.flags_ack == '1':
                    try:
                        i = oneSentList.index("1ACK")
                        oneSentList[i] = "DONE"
                        oneSentUnresolved -= 1
                        eventsNr += 1
                        g.write(f"Event {eventsNr}. Phone 1 sent a text message to Phone 2, which is {oneSentCharList[i]} characters long\n")

                    except ValueError:
                        pass
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