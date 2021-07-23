import pyshark
import asyncio
from collections import defaultdict

def main():
    d = defaultdict(int)
    capture = pyshark.FileCapture('20210723-172114.pcap', display_filter="tcp")

    for pkt in capture:
        try:
            # print(str(pkt.ip.src), str(pkt.tcp.field_names), sep=", ")
            # print(pkt.ip.len)
            if d[pkt.tcp.seq] == 0:
                if pkt.ip.len == '848':
                    pkt.pretty_print()
           # d[pkt.tcp.ack] = 1
        except AttributeError:
            continue

    capture.close()
if __name__ == '__main__':
    main()