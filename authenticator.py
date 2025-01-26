from scapy.all import *
from scapy.layers.eap import EAP, EAPOL
from scapy.layers.l2 import Ether
from eap_constants import *


class EAPAuthenticator:
    def __init__(self, iface):
        self.iface = iface
        self.server_mac = get_if_hwaddr(iface)

    def send_eap_request_identity(self, _packet):
        print("[Server <-- Client]: Received EAPOL-Start")
        eap_request = Ether(dst=_packet.src, src=self.server_mac, type=EAPOL_TYPE_EAP) / EAPOL(version=1, type=0) / EAP(code=EAP_CODE_REQUEST, id=1, type=EAP_TYPE_IDENTITY)
        sendp(eap_request, iface=self.iface, verbose=False)
        print("[Server --> Client]: Sent EAP-Request/Identity")

    def send_eap_request_md5_challenge(self, _packet):
        print("[Server <-- Client]: Received EAP-Response/Identity")
        eap_request = Ether(dst=_packet.src, src=self.server_mac, type=EAPOL_TYPE_EAP) / EAPOL(version=1, type=0) / EAP(code=EAP_CODE_REQUEST, id=2, type=EAP_TYPE_MD5_CHALLENGE) / "md5_challenge"
        sendp(eap_request, iface=self.iface, verbose=False)
        print("[Server --> Client]: Sent EAP-Request/MD5-Challenge")

    def send_eap_success(self, _packet):
        print("[Server <-- Client]: Received EAP-Response/MD5-Challenge")
        eap_success = Ether(dst=_packet.src, src=self.server_mac, type=EAPOL_TYPE_EAP) / EAPOL(version=1, type=0) / EAP(code=EAP_CODE_SUCCESS, id=2)
        sendp(eap_success, iface=self.iface, verbose=False)
        print("[Server --> Client]: Sent EAP-Success")

    def send_eap_failure(self, _packet):
        eap_failure = Ether(dst=_packet.src, src=self.server_mac, type=EAPOL_TYPE_EAP) / EAPOL(version=1, type=0) / EAP(code=EAP_CODE_FAILURE, id=2)
        sendp(eap_failure, iface=self.iface, verbose=False)
        print("[Server --> Client]: Sent EAP-Failure")

    def handle_eapol_start(self, _packet):
        self.send_eap_request_identity(_packet)

    def handle_eap_packet(self, _packet):
        if not _packet.haslayer(EAP):
            return
        if _packet[EAP].code == EAP_CODE_RESPONSE:
            if _packet[EAP].type == EAP_TYPE_IDENTITY:
                self.handle_eap_response_identity(_packet)
            elif _packet[EAP].type == EAP_TYPE_MD5_CHALLENGE:
                self.handle_eap_response_md5_challenge(_packet)
            else:
                print('unknown eap[%s] package' % _packet[EAP].type)


    def handle_eap_response_identity(self, _packet):
        self.send_eap_request_md5_challenge(_packet)

    def handle_eap_response_md5_challenge(self, _packet):
        self.send_eap_success(_packet)

    def handle_handshake_request(self, dst_mac):
        eap_success = Ether(dst=dst_mac, src=self.server_mac, type=EAPOL_TYPE_EAP) / EAPOL(version=1, type=0) / EAP(code=EAP_CODE_SUCCESS, id=2)
        sendp(eap_success, iface=self.iface, verbose=False)
        print("[Server --> Client]: Sent Handshake-Request")


    def start_authentication(self):
        def packet_callback(_packet):
            if _packet.haslayer(EAPOL):
                if _packet[EAPOL].type == EAPOL_TYPE_EAPOL_START:  # EAPOL-Start
                    self.handle_eapol_start(_packet)
                elif _packet[EAPOL].type == EAPOL_TYPE_EAP_PACKET:  # EAP-_packet:
                    self.handle_eap_packet(_packet)
                else:
                    print('unknown eapol type:%s' % _packet[EAPOL].type)
        while True:
            sniff(iface=self.iface, prn=packet_callback, filter="ether proto 0x888e")


def server_thread_start(service):
    thread = threading.Thread(target=service.start_authentication)
    thread.start()



# Example usage
if __name__ == "__main__":
    server = EAPAuthenticator(iface="以太网")
    server_thread_start(server)
