from asyncio.windows_events import NULL
import pyshark

def main():
    c = pyshark.FileCapture('20210728-141207.cap', display_filter="(ip.src == 216.239.36.128 || ip.src == 216.239.36.127 || ip.src == 216.239.36.129 || ip.src == 10.0.0.1) && (ip.dst == 10.0.0.1 || ip.dst == 216.239.36.129 || ip.dst == 216.239.36.128 || ip.dst == 216.239.36.127)")
    capture = list(c)
    c.close()
    g = open("output.txt", 'w')
    eventsNr = 0
    oneSentUnresolved = False
    twoSentList = ["2PUSH", "1PUSH", "2ACK", "1ACK", "1PUSH", "2ACK", "2PUSH", "1ACK"]
    prev = NULL

    i = 0
    while i < len(capture):
        try:
            if capture[i].ip.src == '10.0.0.1' and capture[i].ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                    and capture[i].ip.len == '327' and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 is writing a message for Phone 2\n")
                oneSentUnresolved = False

            elif capture[i].ip.dst == '10.0.0.1' and capture[i].ip.src in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                    and capture[i].ip.len == '848' and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 is writing a message for Phone 1\n")
                oneSentUnresolved = False

            
            elif capture[i].ip.src == '10.0.0.1' and capture[i].ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                and capture[i].ip.len == '491' and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 1 has seen a message from Phone 2\n")
                oneSentUnresolved = False

            elif capture[i].ip.dst == '10.0.0.1' and capture[i].ip.src in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                and capture[i].ip.len == '977' and capture[i].tcp.flags_push == '1':
                eventsNr += 1
                g.write(f"Event {eventsNr}. Phone 2 has seen a message from Phone 1\n")
                oneSentUnresolved = False 
            

            elif capture[i].ip.dst == '10.0.0.1' and capture[i].ip.src in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                and int(capture[i].ip.len) >= 754 and capture[i].tcp.flags_push == '1':
                nr = int(capture[i].ip.len) - 753
                j = i + 1
                b = True
                for k in range(1, 8):
                    if j > len(capture):
                        b = False
                        break
                    if twoSentList[k][0] == '1' \
                        and not(capture[j].ip.src == '10.0.0.1' and capture[j].ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130']):
                        b = False
                        break
                    if twoSentList[k][0] == '2' \
                        and not(capture[j].ip.dst == '10.0.0.1' and capture[j].ip.src in ['216.239.36.128', '216.239.36.129','216.239.36.130']):
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


            elif capture[i].ip.src == '10.0.0.1' and capture[i].ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130'] \
                and int(capture[i].ip.len) >= 250 and capture[i].tcp.flags_push == '1' and (prev == NULL or prev.ip.len == '576'):
                nr = int(capture[i].ip.len) - 250
                oneSentUnresolved = True
                expected = "2ACK"
            
            elif oneSentUnresolved == True and capture[i].ip.dst == '10.0.0.1' and capture[i].ip.src in ['216.239.36.128', '216.239.36.129','216.239.36.130']:
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

            elif oneSentUnresolved == True and capture[i].ip.src == '10.0.0.1' and capture[i].ip.dst in ['216.239.36.128', '216.239.36.129','216.239.36.130']:
                if capture[i].tcp.flags_ack == '1' and capture[i].ip.len == '40':
                    if expected == "1ACK":
                        eventsNr += 1
                        g.write(f"Event {eventsNr}. Phone 1 sent a text message to Phone 2, which is {nr} characters long\n")
                oneSentUnresolved = False

            prev = capture[i]
    
            i += 1
        except AttributeError:
            i += 1
            continue

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

#         for capture[i] in capture:
#             try:
#                 # print(str(capture[i].ip.src), str(capture[i].tcp.field_names), sep=", ")
#                 # print(capture[i].ip.len)
#                 if d[capture[i].tcp.seq] == 0 and d[capture[i].tcp.ack] == 0:             #new stream of events
#                     streamsNr += 1
#                     streamList.append(0)
#                     d[capture[i].tcp.ack] = streamsNr
#                     if capture[i].ip.src == '10.0.0.1' and (capture[i].ip.dst ==  '216.239.36.128' or capture[i].ip.dst ==  '216.239.36.129' or capture[i].ip.dst ==  '216.239.36.130'):
#                         streamList[streamsNr] = 1

#                     d[capture[i].tcp.seq] = -streamsNr
#                     d[capture[i].tcp.ack] = streamsNr


#                 elif d[capture[i].tcp.seq] > 0:
#                     if streamList[d[capture[i].tcp.seq]] == 1 and capture[i].ip.src == '10.0.0.1' and (capture[i].ip.dst ==  '216.239.36.128' or capture[i].ip.dst ==  '216.239.36.129' or capture[i].ip.dst ==  '216.239.36.130') \
#                         and capture[i].ip.len == '327' and capture[i].tcp.flags_psh == '1':
#                         streamList[d[capture[i].tcp.seq]] = 3
#                         g.write("Phone 1 is writing a text message intended for phone 2")

#                     # else:


#                     # if capture[i].ip.len == '327':
#                     #     print(capture[i].layers)
#             # d[capture[i].tcp.ack] = 1
#             except AttributeError:
#                 continue

#         capture.close()
# if __name__ == '__main__':
#     main()