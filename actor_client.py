from scapy.all import *
from constants import *

from scapy.layers.eap import EAP, EAPOL
from scapy.layers.l2 import Ether, ARP


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
        eap = packet[EAP]
        md5_challenge = hashlib.md5(bytes([eap.id]) + b"secret" + eap.value[:eap.value_size]).digest()
        data = bytes([16]) + md5_challenge
        print('Client: eap:id[%s], md5-challenge[%s]' % (eap.id, md5_challenge))

        eap_response = Ether(dst=self.server_mac, src=self.client_mac, type=EAPOL_TYPE_EAP) / \
                       EAPOL(version=1, type=0) / \
                       EAP(code=EAP_CODE_RESPONSE, id=packet[EAP].id, type=EAP_TYPE_MD5_CHALLENGE) / \
                       Raw(load=data)
        sendp(eap_response, iface=self.iface, verbose=False)
        print("[Server <-- Client]: Sent EAP-Response/MD5-Challenge")

    def handle_eap_request(self, packet):
        if packet[EAP].type == EAP_TYPE_IDENTITY:
            self.send_eap_response_identity(packet)
        elif packet[EAP].type == EAP_TYPE_MD5_CHALLENGE:
            self.send_eap_response_md5_challenge(packet)

    def handle_eap_success(self, packet):
        print("[Server --> Client]: Received EAP-Success")

    def handle_eap_failure(self, packet):
        print("[Server --> Client]: Received EAP-Failure")

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
    client = EAPSupplicant(iface="VMnet8", server_mac="00:0c:29:6b:12:5f")
    client.start_authentication()
