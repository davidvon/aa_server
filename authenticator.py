from scapy.all import *
from scapy.layers.eap import EAP, EAPOL
from scapy.layers.l2 import Ether
from threading import Thread, Lock
from queue import Queue
from eap_constants import *
from radius_handler import RadiusHandler


class EAPAuthenticator:
    def __init__(self, interface, radius_config):
        self.interface = interface
        self.mac = get_if_hwaddr(interface)
        self.radius = RadiusHandler(
            server=radius_config['server'],
            secret=radius_config['secret'],
            nas_ip=radius_config['nas_ip'],
            mode=radius_config.get('mode', MODE_RELAY)
        )
        self.sessions = {}
        self.session_lock = Lock()
        self.workers = []
        self.packet_queue = Queue()
        self.running = False

        # 注册处理方法
        self.handlers = {
            EAP_IDENTITY: self._handle_identity_request,
            EAP_MD5: self._handle_md5_challenge_request,
            EAP_TLS: self._handle_tls_request,
            EAP_PEAP: self._handle_peap_request
        }
        print('mac:', self.mac)

    def start(self):
        """启动认证服务"""
        self.running = True
        # 抓包线程
        Thread(target=self._sniff_loop, daemon=True).start()
        # 工作线程
        for _ in range(4):
            worker = Thread(target=self._process_worker)
            worker.start()
            self.workers.append(worker)
        print(f"Authenticator started on {self.interface}")

    def _sniff_loop(self):
        """抓包循环"""
        sniff(iface=self.interface, prn=self.packet_queue.put,
              filter=f"ether proto {EAPOL_TYPE_EAP}", store=False)

    def _process_worker(self):
        """工作线程处理"""
        while self.running or not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get(timeout=1)
                self._dispatch_packet(pkt)
            except Empty:
                continue

    def _dispatch_packet(self, pkt):
        """分发数据包处理"""
        if EAPOL in pkt and pkt[EAPOL].type == EAPOL_TYPE_EAPOL_START:
            self._handle_eapol_start(pkt)
        elif EAP in pkt and pkt[EAP].code == EAP_RESPONSE:
            self._process_eap_response(pkt)

    def _handle_eapol_start(self, pkt):
        """处理EAPOL-Start"""
        client_mac = pkt.src
        with self.session_lock:
            self.sessions[client_mac] = {
                'id': f"{time.time():.0f}",
                'username': None,
                'state': None
            }
        self._send_eap_request(EAP_IDENTITY, client_mac)

    def _process_eap_response(self, pkt):
        """处理EAP响应"""
        client_mac = pkt.src
        eap = pkt[EAP]

        if self.radius.mode == MODE_RELAY:
            self._relay_to_radius(client_mac, eap)
        else:
            handler = self.handlers.get(eap.type)
            if handler:
                handler(client_mac, eap)

    def _relay_to_radius(self, client_mac, eap):
        """中继模式处理"""
        with self.session_lock:
            session = self.sessions.get(client_mac)
        if not session:
            return

        req = self.radius.create_request(
            username=session.get('username', 'unknown'),
            eap_data=eap.build()
        )
        if resp := self.radius.process(req):
            self._handle_radius_response(client_mac, resp)

    def _handle_radius_response(self, client_mac, resp):
        """处理RADIUS响应"""
        if resp.code == ACCESS_ACCEPT:
            self._send_eap_result(EAP_SUCCESS, client_mac)
        elif resp.code == ACCESS_CHALLENGE:
            self._send_eap_request(EAP_MD5, client_mac, resp["EAP-Message"][0])
        else:
            self._send_eap_result(EAP_FAILURE, client_mac)

    # 以下是终结模式处理方法
    def _handle_identity_request(self, client_mac, eap):
        """处理身份认证"""
        username = eap.load.decode().strip('\x00')
        with self.session_lock:
            self.sessions[client_mac]['username'] = username
        self._send_md5_challenge(client_mac)

    def _send_md5_challenge(self, client_mac):
        """发送MD5挑战"""
        challenge = os.urandom(16)
        with self.session_lock:
            self.sessions[client_mac]['challenge'] = challenge
        challenge_pkt = bytes([16]) + challenge
        self._send_eap_request(EAP_MD5, client_mac, challenge_pkt)

    def _handle_md5_challenge_request(self, client_mac, eap):
        """验证MD5响应"""
        with self.session_lock:
            session = self.sessions.get(client_mac)

        if not session or 'challenge' not in session:
            return

        # 生成预期响应（示例密码"secret"）
        expected = hashlib.md5(
            bytes([eap.id]) + b"secret" + session['challenge']
        ).digest()

        if eap.load[1:17] == expected:
            self._send_eap_result(EAP_SUCCESS, client_mac)
        else:
            self._send_eap_result(EAP_FAILURE, client_mac)

    def _send_eap_request(self, eap_type, dst_mac, data=None):
        """发送EAP请求"""
        eap = EAP(code=EAP_REQUEST, id=os.urandom(1)[0], type=eap_type)
        if data:
            eap /= Raw(load=data)

        pkt = Ether(dst=dst_mac, src=self.mac) / EAPOL(version=EAPOL_VERSION) / eap
        sendp(pkt, iface=self.interface, verbose=0)

    def _send_eap_result(self, code, dst_mac):
        """发送认证结果"""
        pkt = Ether(dst=dst_mac, src=self.mac) / EAPOL(version=EAPOL_VERSION)
        pkt /= EAP(code=code, id=os.urandom(1)[0])
        sendp(pkt, iface=self.interface, verbose=0)

    # TLS/PEAP处理占位符（实现略）
    def _handle_tls_request(self, *args):
        pass

    def _handle_peap_request(self, *args):
        pass



if __name__ == '__main__':
    config_relay = {
        'server': '192.168.253.141',
        'secret': 'testing123',
        'nas_ip': '127.0.1.1',
        'mode': MODE_RELAY
    }

    # 终结模式配置
    config_terminate = {
        'server': '',  # 终结模式不需要真实服务器
        'secret': 'testing123',
        'nas_ip': '192.168.1.100',
        'mode': MODE_TERMINATE
    }
    authenticator = EAPAuthenticator("en0", config_relay)
    authenticator.start()

    # 保持主线程运行
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        authenticator.running = False
