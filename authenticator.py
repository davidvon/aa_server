import time

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
        for _ in range(1):
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
        while self.running:
            time.sleep(0.2)
            try:
                if self.packet_queue.empty():
                    continue
                pkt = self.packet_queue.get(timeout=1)
                if not pkt:
                    continue
                self._dispatch_packet(pkt)
            except Exception as e:
                print(e.__repr__())

    def _dispatch_packet(self, pkt):
        """分发数据包处理"""
        print('received packet', pkt)
        if EAPOL in pkt and pkt[EAPOL].type == EAPOL_TYPE_EAPOL_START:
            self._handle_eapol_start(pkt)
        elif EAP in pkt and pkt[EAP].code == EAP_RESPONSE:
            self._process_eap_response(pkt)

    def _handle_eapol_start(self, pkt):
        """处理EAPOL-Start"""
        dst_mac = pkt.src
        if dst_mac in self.sessions.keys() and self.sessions[dst_mac]['state'] >= STATE_STEP_REQ_START:
            print('[Server <-- Client(%s)]: state:%s exists.' % (self.sessions[dst_mac]['id'], self.sessions[dst_mac].get('state')))
            return

        with self.session_lock:
            self.sessions[dst_mac] = {
                'id': os.urandom(1)[0],
                'ts': f"{time.time():.0f}",
                'username': None,
                'state': STATE_STEP_REQ_START
            }
        self._send_eap_request(EAP_IDENTITY, dst_mac)

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

        username = session.get('username') or 'unknown'
        eap_data = eap.build()
        resp = self.radius.send_request(
            username=username,
            eap_data=eap_data
        )
        self._handle_radius_response(client_mac, resp)

    def _handle_radius_response(self, client_mac, resp):
        """处理RADIUS响应"""
        if resp is None or resp.code == ACCESS_ACCEPT:
            self._send_eap_result(EAP_SUCCESS, client_mac)
        elif resp.code == ACCESS_CHALLENGE:
            self._send_eap_request(EAP_MD5, client_mac, resp["EAP-Message"][0])
        else:
            self._send_eap_result(EAP_FAILURE, client_mac)

    # 以下是终结模式处理方法
    def _send_md5_challenge(self, client_mac, challenge):
        """发送MD5挑战"""
        challenge_pkt = bytes([16]) + challenge
        self._send_eap_request(EAP_MD5, client_mac, challenge_pkt)

    def _handle_identity_request(self, client_mac, eap):
        """处理身份认证"""
        if self.sessions[client_mac]['state'] >= STATE_STEP_ACK_IDENTITY:
            print('[Server <-- Client(%s)]: state:%s exists.' % (self.sessions[client_mac]['id'], self.sessions[client_mac].get('state')))
            return
        challenge = os.urandom(16)
        with self.session_lock:
            self.sessions[client_mac]['challenge'] = challenge
            self.sessions[client_mac]['username'] = str(eap.identity, encoding="utf-8")
            self.sessions[client_mac]['state'] = STATE_STEP_ACK_IDENTITY
        self._send_md5_challenge(client_mac, challenge)

    def _handle_md5_challenge_request(self, client_mac, eap):
        """验证MD5"""
        if self.sessions[client_mac]['state'] >= STATE_STEP_ACK_MD5_CHALLENGE:
            print('[Server <-- Client(%s)]: state:%s exists.' % (self.sessions[client_mac]['id'], self.sessions[client_mac].get('state')))
            return
        with self.session_lock:
            session = self.sessions.get(client_mac)
            self.sessions[client_mac]['state'] = STATE_STEP_ACK_MD5_CHALLENGE
        print('[Server <-- Client(%s)]: challenge[%s]' % (eap.id, session['challenge']))
        expected = hashlib.md5(bytes([eap.id]) + b"secret" + session['challenge']).digest()
        self._send_eap_result(EAP_SUCCESS if eap.value == expected else EAP_FAILURE, client_mac)

    def _send_eap_request(self, eap_type, dst_mac, data=None):
        """发送EAP请求"""
        eap_id = self.sessions[dst_mac]['id']
        eap = EAP(code=EAP_REQUEST, id=eap_id, type=eap_type)
        if data:
            eap /= Raw(load=data)
        pkt = Ether(dst=dst_mac, src=self.mac) / EAPOL(version=EAPOL_VERSION) / eap
        sendp(pkt, iface=self.interface, verbose=0)
        print('[Server --> Client[%d]]: ACCESS CHALLENGE' % eap_id)

    def _send_eap_result(self, code, dst_mac):
        eap_id = self.sessions[dst_mac]['id']
        """发送认证结果"""
        pkt = Ether(dst=dst_mac, src=self.mac) / EAPOL(version=EAPOL_VERSION)
        pkt /= EAP(code=code, id=os.urandom(1)[0])
        sendp(pkt, iface=self.interface, verbose=0)
        print('[Server --> Client[%d]]: ACCESS %s' % (eap_id, 'SUCCESS' if code == EAP_SUCCESS else 'FAILURE'))

    # TLS/PEAP处理占位符（实现略）
    def _handle_tls_request(self, client_mac, eap):
        pass

    def _handle_peap_request(self, client_mac, eap):
        pass


if __name__ == '__main__':
    config_relay = {
        'server': '192.168.3.24',
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
    authenticator = EAPAuthenticator("en1", config_terminate)
    authenticator.start()

    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        authenticator.running = False
