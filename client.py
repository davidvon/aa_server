from scapy.all import *
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.l2 import Ether
from eap_constants import *
import threading
import time
import hashlib


class EAPClient:
    def __init__(self, interface, server_mac, username, password):
        self.interface = interface
        self.server_mac = server_mac
        self.client_mac = get_if_hwaddr(interface)
        self.username = username
        self.password = password.encode()
        self.running = False
        self.eap_id = 0  # EAP 标识符计数器
        self.handlers = {
            EAP_IDENTITY: self.handle_identity_request,
            EAP_MD5: self.handle_md5_challenge_request,
            EAP_TLS: self.handle_tls_request,
            EAP_PEAP: self.handle_peap_request
        }

    def start(self):
        """启动客户端认证流程"""
        self.running = True
        # 启动接收线程
        recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        recv_thread.start()
        # 发送 EAPOL-Start
        self.send_eapol_start()
        print(f"[Client] 客户端已启动，等待认证...")

    def stop(self):
        """停止客户端"""
        self.running = False
        print("[Client] 客户端已停止")

    def _recv_loop(self):
        """接收数据包循环"""
        sniff_filter = f"ether proto {EAPOL_TYPE_EAP} and dst host {self.client_mac}"
        while self.running:
            sniff(iface=self.interface, prn=self._process_packet, filter=sniff_filter, store=0, timeout=1)

    def _process_packet(self, pkt):
        """处理接收到的数据包"""
        if EAP in pkt and pkt[EAP].code == EAP_REQUEST:
            eap = pkt[EAP]
            handler = self.handlers.get(eap.type)
            if handler:
                handler(eap)
            else:
                print(f"[Client] 未知的 EAP 类型: {eap.type}")
        elif EAP in pkt and pkt[EAP].code in [EAP_SUCCESS, EAP_FAILURE]:
            self.handle_eap_result(pkt[EAP])

    def send_eapol_start(self):
        """发送 EAPOL-Start"""
        eapol_start = Ether(dst=self.server_mac, src=self.client_mac, type=EAPOL_TYPE_EAP)
        eapol_start /= EAPOL(version=EAPOL_VERSION, type=EAPOL_TYPE_EAPOL_START)
        sendp(eapol_start, iface=self.interface, verbose=0)
        print("[Client] 发送 EAPOL-Start")

    def send_eap_response(self, eap_type, eap_id, data=None):
        """发送 EAP 响应"""
        eap = EAP(code=EAP_RESPONSE, id=eap_id, type=eap_type)
        if data:
            eap /= Raw(load=data)

        pkt = Ether(dst=self.server_mac, src=self.client_mac, type=EAPOL_TYPE_EAP)
        pkt /= EAPOL(version=EAPOL_VERSION, type=0)
        pkt /= eap
        sendp(pkt, iface=self.interface, verbose=0)
        print(f"[Client] 发送 EAP-Response (类型: {eap_type})")

    def handle_identity_request(self, eap):
        """处理 EAP-Request/Identity"""
        print("[Client] 收到 EAP-Request/Identity")
        self.send_eap_response(EAP_IDENTITY, eap.id, self.username.encode())

    def handle_md5_challenge_request(self, eap):
        """处理 EAP-Request/MD5-Challenge"""
        print("[Client] 收到 EAP-Request/MD5-Challenge")
        challenge = eap.load[1:17]  # 提取挑战值
        response = self._generate_md5_response(eap.id, challenge)
        self.send_eap_response(EAP_MD5, eap.id, response)

    def _generate_md5_response(self, eap_id, challenge):
        """生成 MD5 挑战响应"""
        md5_data = bytes([eap_id]) + self.password + challenge
        md5_hash = hashlib.md5(md5_data).digest()
        return bytes([16]) + md5_hash  # 响应格式: 长度(1字节) + 哈希值(16字节)

    def handle_tls_request(self, eap):
        """处理 EAP-Request/TLS"""
        print("[Client] 收到 EAP-Request/TLS")
        # 示例：发送空的 TLS 响应
        self.send_eap_response(EAP_TLS, eap.id, b"\x01\x00\x00\x04")

    def handle_peap_request(self, eap):
        """处理 EAP-Request/PEAP"""
        print("[Client] 收到 EAP-Request/PEAP")
        # 示例：发送空的 PEAP 响应
        self.send_eap_response(EAP_PEAP, eap.id, b"\x02\x00\x00\x08")

    def handle_eap_result(self, eap):
        """处理 EAP-Success 或 EAP-Failure"""
        if eap.code == EAP_SUCCESS:
            print("[Client] 认证成功！")
        else:
            print("[Client] 认证失败！")
        self.stop()


# 示例运行
if __name__ == "__main__":
    """ 启动客户端
    python client.py --interface eth0 --server-mac 00:11:22:33:44:55 --username test_user --password test_password
    """
    client = EAPClient(
        interface="en0",
        server_mac="3c:07:54:77:fe:b9",
        username="operator",
        password="testpass"
    )
    try:
        client.start()
        while client.running:
            time.sleep(1)
    except KeyboardInterrupt:
        client.stop()

