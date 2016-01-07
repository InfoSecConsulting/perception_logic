from logging import getLogger
from scapy.all import *

getLogger("scapy.runtime").setLevel(1)


def tcp_scan(host, port):
  tcp_connect_scan_resp = sr1(IP(dst=host) / TCP(dport=port, flags='S'), timeout=10, verbose=0)

  if str(type(tcp_connect_scan_resp)) == "<type 'None Type'>":
    return False

  if tcp_connect_scan_resp is not None:

    if TCP in tcp_connect_scan_resp:

      if tcp_connect_scan_resp.getlayer(TCP).flags == 0x12:

        sr(IP(dst=host) / TCP(dport=port, flags='AR'), timeout=10)

        return True

      elif tcp_connect_scan_resp.getlayer(TCP).flags == 0x14:

         return False
