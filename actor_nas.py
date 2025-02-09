from scapy.all import *
from scapy.layers.eap import EAP, EAPOL
from scapy.layers.l2 import Ether
from threading import Thread, Lock
from queue import Queue
from constants import *
from handlers.radius_client_handler import RadiusClientHandler


class NasService:
    def __init__(self, interface, config):
        self.interface = interface
        self.mac = get_if_hwaddr(interface)
        self.radius_mode = config.get('mode')
        if self.radius_mode == MODE_RELAY:
            self.radius = RadiusClientHandler(config)
        self.users = config.get('users')
        self.sessions = {}
        self.session_lock = Lock()
        self.workers = []
        self.packet_queue = Queue()
        self.running = False

        # 注册处理方法
        self.handlers = {
            EAP_IDENTITY: self._handle_response_identity,
            EAP_MD5: self._handle_response_md5_challenge,
            EAP_TLS: self._handle_response_tls,
            EAP_PEAP: self._handle_response_peap
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
        print(f"NAS-Service starting on {self.interface}")

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
        if EAPOL in pkt and pkt[EAPOL].type == EAPOL_TYPE_EAPOL_START:
            self._handle_eapol_start(pkt)
        elif EAP in pkt and pkt[EAP].code == EAP_RESPONSE:
            self._handle_eap_response(pkt)

    def _handle_eap_response(self, pkt):
        """处理EAP响应"""
        client_mac = pkt.src
        eap = pkt[EAP]
        if self.radius_mode == MODE_RELAY:
            self._handle_relay_to_radius(client_mac, eap)
        elif self.handlers.get(eap.type):
            self.handlers[eap.type](client_mac, eap)

    def _handle_eapol_start(self, pkt):
        """处理EAPOL-Start"""
        client_mac = pkt.src
        print('[Server <-- Client(%s)]: Received EAPOL-Start' % client_mac)
        # if client_mac in self.sessions.keys() and self.sessions[client_mac]['state'] >= STATE_STEP_REQ_START:
            # print('[Server <-- Client(%s)][%s]: cache to clear.' % (client_mac, self.sessions[client_mac]['id']))
        if client_mac in self.sessions.keys() and self.sessions[client_mac]['state'] == STATE_STEP_REQ_START:
            return
        with self.session_lock:
            self.sessions[client_mac] = {
                'id': 0,
                'ts': time.time(),
                'username': None,
                'state': STATE_STEP_REQ_START
            }
        self._send_eap_request(EAP_IDENTITY, client_mac)
        print('[Server --> Client(%s)][%s]: Sent EAP-Request/Identity' % (client_mac, self.sessions[client_mac]['id']))


    def _handle_relay_to_radius(self, client_mac, eap):
        """中继模式处理"""
        print('[Server <-- Client(%s)][%s][Relay]: Received EAP-Response' % (client_mac, eap.id))
        resp = self.radius.send_relay_request(eap_data=eap.build())
        # 处理RADIUS响应
        if resp.code == ACCESS_ACCEPT:
            self._send_eap_result(EAP_SUCCESS, client_mac)
            print('[Server --> Client(%s)][%s][Relay] Sent Success' % (client_mac, self.sessions[client_mac]['id']))
        elif resp.code == ACCESS_CHALLENGE:
            self._send_eap_request(EAP_MD5, client_mac, resp["EAP-Message"][0])
            print('[Server --> Client(%s)][%s][Relay]: Sent EAP-Request/MD5-Challenge' % (client_mac,self.sessions[client_mac]['id']))
        else:
            self._send_eap_result(EAP_FAILURE, client_mac)
            print('[Server --> Client(%s)][%s][Relay] Sent Failure:%s'% (client_mac, self.sessions[client_mac]['id'], resp.code))

    # 以下是终结模式处理方法
    def _handle_response_identity(self, client_mac, eap):
        """处理身份认证"""
        if self.sessions[client_mac]['state'] >= STATE_STEP_ACK_IDENTITY:
            # print('[Server <-- Client(%s)][%s]: Received EAP-Response/Identity, state:%s exists, discard!' % (client_mac, eap.id, self.sessions[client_mac].get('state')))
            return
        print('[Server <-- Client(%s)][%s]: Received EAP-Response/Identity' % (client_mac, eap.id))
        challenge = os.urandom(16)
        username = self._get_user(str(eap.identity))
        if not username:
            self._send_eap_result(EAP_FAILURE, client_mac)
            return
        with self.session_lock:
            self.sessions[client_mac]['challenge'] = challenge
            self.sessions[client_mac]['username'] = username
            self.sessions[client_mac]['state'] = STATE_STEP_ACK_IDENTITY
        challenge_pkt = bytes([16]) + challenge
        self._send_eap_request(EAP_MD5, client_mac, challenge_pkt)
        print('[Server --> Client(%s)][%s]: Sent EAP-Request/MD5-Challenge' % (client_mac, self.sessions[client_mac]['id']))


    def _handle_response_md5_challenge(self, client_mac, eap):
        """验证MD5"""
        challenge = self.sessions[client_mac]['challenge']
        password = self.users[self.sessions[client_mac]['username']]
        state = self.sessions[client_mac]['state']
        if state >= STATE_STEP_ACK_MD5_CHALLENGE:
            # print('[Server <-- Client(%s)][%s]: Received EAP-Response/MD5-Challenge, state:%s exists, discard!' % (client_mac, eap.id, state))
            return
        print('[Server <-- Client(%s)][%s]: Received EAP-Response/MD5-Challenge' % (client_mac, eap.id))
        with self.session_lock:
            self.sessions[client_mac]['state'] = STATE_STEP_ACK_MD5_CHALLENGE

        expected = hashlib.md5(bytes([eap.id]) + password.encode() + challenge).digest()
        if eap.value != expected:
            print('[Server --> Client(%s)][%s]: MD5 CHECK FAILURE, expect:%s, actual:%s' % (client_mac, self.sessions[client_mac]['id'], expected, eap.value))
        self._send_eap_result(EAP_SUCCESS if eap.value == expected else EAP_FAILURE, client_mac)
        print('[Server --> Client(%s)][%s]: Sent SUCCESS' % (client_mac, self.sessions[client_mac]['id']))


    # TLS/PEAP处理占位符（实现略）
    def _handle_response_tls(self, client_mac, eap):
        print('[Server <-- Client(%s)][%s]: Received EAP-Response/TLS' % (client_mac, eap.id))
        pass

    def _handle_response_peap(self, client_mac, eap):
        print('[Server <-- Client(%s)][%s]: Received EAP-Response/PEAP' % (client_mac, eap.id))
        pass

    def _send_eap_request(self, eap_type, dst_mac, data=None):
        """发送EAP请求"""
        self.sessions[dst_mac]['id'] = self.sessions[dst_mac]['id'] + 1
        eap = EAP(code=EAP_REQUEST, id=self.sessions[dst_mac]['id'], type=eap_type)
        if data:
            eap /= Raw(load=data)
        pkt = Ether(dst=dst_mac, src=self.mac) / EAPOL(version=EAPOL_VERSION) / eap
        sendp(pkt, iface=self.interface, verbose=0)


    def _send_eap_result(self, code, dst_mac):
        """发送认证结果"""
        self.sessions[dst_mac]['id'] += 1
        eap = EAP(code=code, id=self.sessions[dst_mac]['id'])
        pkt = Ether(dst=dst_mac, src=self.mac) / EAPOL(version=EAPOL_VERSION) / eap
        sendp(pkt, iface=self.interface, verbose=0)

    def _get_user(self, identity):
        for item in self.users.keys():
            if item in identity:
                return item
        return None


if __name__ == '__main__':
    config_relay = {
        'server': '127.0.0.1',
        'auth_port': 1812,
        'secret': 'testing123',
        'users': {
            'operator':'testpass',
            '0252000621':'ZTE123456'
        },
        'mode': MODE_RELAY
    }

    # 终结模式配置
    config_terminate = {
        'server': '127.0.0.1',
        'auth_port': 1812,
        'username': 'operator',
        'users': {
            'operator':'testpass',
            '0252000621':'ZTE123456'
        },
        'mode': MODE_TERMINATE
    }
    authenticator = NasService("ens33", config_terminate)
    authenticator.start()

    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        authenticator.running = False
