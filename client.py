from scapy.all import *
import time

from scapy.layers.eap import EAP, EAPOL
from scapy.layers.l2 import Ether

# 定义EAPOL类型
EAPOL_TYPE_EAP = 0x888e

# 定义EAP代码
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4

# 定义EAP类型
EAP_TYPE_IDENTITY = 1
EAP_TYPE_MD5_CHALLENGE = 4

class EAPSupplicant:
    def __init__(self, iface, server_mac):
        self.iface = iface
        self.server_mac = server_mac
        self.client_mac = get_if_hwaddr(iface)

    def send_eapol_start(self):
        eapol_start = Ether(dst=self.server_mac, src=self.client_mac, type=EAPOL_TYPE_EAP) / \
                      EAPOL(version=1, type=1)  # EAPOL-Start
        sendp(eapol_start, iface=self.iface, verbose=False)
        print("[Server <-- Client]: Sent EAPOL-Start")

    def send_eap_response_identity(self, packet):
        print("[Server --> Client]: Received EAP-Request/Identity")
        eap_response = Ether(dst=self.server_mac, src=self.client_mac, type=EAPOL_TYPE_EAP) / \
                       EAPOL(version=1, type=0) / \
                       EAP(code=EAP_CODE_RESPONSE, id=packet[EAP].id, type=EAP_TYPE_IDENTITY) / \
                       "client_identity"
        sendp(eap_response, iface=self.iface, verbose=False)
        print("[Server <-- Client]: Sent EAP-Response/Identity")

    def send_eap_response_md5_challenge(self, packet):
        print("[Server --> Client]: Received EAP-Request/MD5-Challenge")
        eap_response = Ether(dst=self.server_mac, src=self.client_mac, type=EAPOL_TYPE_EAP) / \
                       EAPOL(version=1, type=0) / \
                       EAP(code=EAP_CODE_RESPONSE, id=packet[EAP].id, type=EAP_TYPE_MD5_CHALLENGE) / \
                       "md5_challenge_response"
        sendp(eap_response, iface=self.iface, verbose=False)
        print("[Server <-- Client]: Sent EAP-Response/MD5-Challenge")

    def handle_eap_request(self, packet):
        if packet[EAP].type == EAP_TYPE_IDENTITY:
            self.send_eap_response_identity(packet)
        elif packet[EAP].type == EAP_TYPE_MD5_CHALLENGE:
            self.send_eap_response_md5_challenge(packet)

    def handle_eap_success(self, packet):
        print("[Server --> Client]: Received EAP-Success")
        print("Authentication Successful!")

    def handle_eap_failure(self, packet):
        print("[Server --> Client]: Received EAP-Failure")
        print("Authentication Failed!")

    def start_authentication(self):
        self.send_eapol_start()

        def packet_callback(packet):
            if packet.haslayer(EAP):
                if packet[EAP].code == EAP_CODE_REQUEST:
                    self.handle_eap_request(packet)
                elif packet[EAP].code == EAP_CODE_SUCCESS:
                    self.handle_eap_success(packet)
                elif packet[EAP].code == EAP_CODE_FAILURE:
                    self.handle_eap_failure(packet)

        while True:
            sniff(iface=self.iface, prn=packet_callback, filter="ether proto 0x888e", timeout=10)


# Example usage
if __name__ == "__main__":
    client = EAPSupplicant(iface="以太网", server_mac="00:16:96:EC:11:53")
    client.start_authentication()
