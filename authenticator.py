from scapy.all import *
from scapy.layers.eap import EAP, EAPOL
from scapy.layers.l2 import Ether
from eap_constants import *
from radius_handler import RadiusHandler


class EAPAuthenticator:
    def __init__(self, iface, radius_config):
        self.iface = iface
        self.mac = get_if_hwaddr(iface)
        self.running = False
        self.sessions = {}  # 客户端会话存储
        self.session_lock = threading.Lock()
        self.sequence_num = 0  # RADIUS请求序列号
        self.radius_handle = RadiusHandler(radius_config, self.mac)

    def _init_session(self, client_mac):
        """初始化会话"""
        with self.session_lock:
            self.sessions[client_mac] = {
                'id': f"{time.time():.0f}",
                'username': None,
                'radius_state': None,
                'start_time': time.time()
            }

    def _send_eap_request(self, eap_type, dst_mac, data=None):
        """发送EAP请求"""
        eap = EAP(code=EAP_CODE_REQUEST, id=self._get_next_id(), type=eap_type)
        if data:
            eap /= Raw(load=data)

        pkt = Ether(dst=dst_mac, src=self.mac, type=EAPOL_TYPE_EAP) / EAPOL(version=EAPOL_VERSION, type=0) / eap
        sendp(pkt, iface=self.iface, verbose=False)
        print(f"[Server --> Client({dst_mac})]: Sent EAP Request[{eap_type}]")


    def _send_eap_result(self, result_code, dst_mac):
        """发送认证结果"""
        pkt = Ether(dst=dst_mac, src=self.mac, type=EAPOL_TYPE_EAP)
        pkt /= EAPOL(version=EAPOL_VERSION, type=0)
        pkt /= EAP(code=result_code, id=self._get_next_id())
        sendp(pkt, iface=self.iface, verbose=0)
        status = "Success" if result_code == EAP_CODE_SUCCESS else "Failure"
        print(f"[Server --> Client({dst_mac})]: {status}")

    def _send_eap_request_identity(self, _packet):
        print("[Server <-- Client]: Received EAPOL-Start: {_packet.src}")
        self._init_session(_packet.src)
        self._send_eap_request(EAP_TYPE_IDENTITY, _packet.src)
        print("[Server --> Client]: Sent EAP-Request/Identity")

    def _send_eap_request_md5_challenge(self, _packet):
        print("[Server <-- Client]: Received EAP-Response/Identity")
        self._send_eap_request(EAP_TYPE_MD5_CHALLENGE, _packet.src, "md5_challenge")

    def send_eap_success(self, _packet):
        print("[Server <-- Client]: Received EAP-Response/MD5-Challenge")
        self._send_eap_result(EAP_CODE_SUCCESS, _packet.src)

    def send_eap_failure(self, _packet):
        self._send_eap_result(EAP_CODE_FAILURE, _packet.src)
        print("[Server --> Client]: Sent EAP-Failure")

    def handle_eapol_start(self, _packet):
        self._send_eap_request_identity(_packet)

    def handle_eap_packet(self, _packet):
        if not _packet.haslayer(EAP):
            return
        if _packet[EAP].code != EAP_CODE_RESPONSE:
            return

        with self.session_lock:
            session = self.sessions.get(_packet.src, None)
        if not session:
            print(f"[WARN] No session for {_packet.src}")
            return

        print(f"[RADIUS Auth] Processing EAP Response type:{_packet[EAP].type} from {_packet.src}")

        radius_req = {
            'eap_payload': _packet[EAP].build(),
            'client_mac': _packet.src,
            'nas_ip': '192.168.1.1',  # NAS设备IP
            'session_id': session['id']
        }
        mode = self.radius_handle.radius_config['mode']
        if mode == RADIUS_MODE_RELAY:           # 中继模式直接转发
            self._relay_to_radius(radius_req, _packet.src)
        elif mode == RADIUS_MODE_TERMINATE:     # 终结模式分阶段处理
            self._handle_terminate_mode(_packet[EAP], _packet.src, session)


        # # 处理不同认证方法
        # if _packet[EAP].type == EAP_TYPE_IDENTITY:
        #     self.handle_eap_response_identity(_packet, session)
        # elif _packet[EAP].type in [EAP_TYPE_TLS, EAP_TYPE_PEAP]:
        #     self._handle_auth_response(_packet, _packet.src, session)



    def _relay_to_radius(self, radius_req, client_mac):
        """中继模式处理逻辑"""
        try:
            # 发送RADIUS Access-Request
            radius_resp = self.radius_handle.process_eap(
                eap_pkt=radius_req['eap_payload'],
                session_state=radius_req.get('state', None)
            )
            # 处理RADIUS响应
            if radius_resp['code'] == RADIUS_ACCESS_CHALLENGE:
                print(f"[RADIUS Relay] Challenge from server for {client_mac}")
                self._handle_radius_challenge(radius_resp, client_mac)
            elif radius_resp['code'] == RADIUS_ACCESS_ACCEPT:
                print(f"[RADIUS Relay] Auth success for {client_mac}")
                self._send_eap_result(EAP_CODE_SUCCESS, client_mac)
            else:
                print(f"[RADIUS Relay] Auth failed for {client_mac}")
                self._send_eap_result(EAP_CODE_FAILURE, client_mac)
        except Exception as e:
            print(f"[ERROR] RADIUS通信失败: {str(e)}")
            self._send_eap_result(EAP_CODE_FAILURE, client_mac)


    def _handle_terminate_mode(self, eap, client_mac, session):
        """终结模式处理逻辑"""
        if eap.type == EAP_TYPE_IDENTITY:
            # 第一阶段：身份验证
            if self._verify_identity(eap.load):
                print(f"[RADIUS Terminate] Identity verified for {client_mac}")
                self._send_eap_request(EAP_TYPE_TLS, client_mac, b'TLS Challenge')
            else:
                self._send_eap_result(EAP_CODE_FAILURE, client_mac)
        elif eap.type in [EAP_TYPE_TLS, EAP_TYPE_PEAP]:
            # 第二阶段：转发到RADIUS
            radius_resp = self.radius_handle.process_eap(eap.build())
            if radius_resp['code'] == RADIUS_ACCESS_ACCEPT:
                self._finalize_authentication(client_mac)
            else:
                self._send_eap_result(EAP_CODE_FAILURE, client_mac)


    def _handle_radius_challenge(self, resp, client_mac):
        """处理挑战响应"""
        # 保存状态属性
        with self.session_lock:
            if client_mac in self.sessions:
                self.sessions[client_mac]['radius_state'] = resp.get('State', b'').decode()
        # 解析EAP消息
        eap_data = resp['EAP-Message'][0]
        if len(eap_data) < 5:
            print("[ERROR] Invalid EAP challenge data")
            return

        code, id, length = struct.unpack('!BBH', eap_data[:4])
        eap_type = eap_data[4]
        payload = eap_data[5:] if length > 5 else b''

        # 转发EAP请求给客户端
        self._send_eap_request(eap_type, client_mac, payload)


    @staticmethod
    def _verify_identity(identity):
        """本地身份验证（示例）"""
        # 此处可扩展LDAP/本地数据库验证
        return identity.decode().startswith("valid_user")


    def _finalize_authentication(self, client_mac):
        """完成认证后的操作"""
        self._send_eap_result(EAP_CODE_SUCCESS, client_mac)
        with self.session_lock:
            if client_mac in self.sessions:
                del self.sessions[client_mac]


    # def handle_eap_response_identity(self, _packet, session):
    #     username = _packet[EAP].load.decode('utf-8', errors='ignore').strip('\x00')
    #     print(f"[RADIUS Auth] Received identity: {username}")
    #     with self.session_lock:
    #         self.sessions[_packet.src]['username'] = username
    #
    #     # 根据模式处理
    #     if self.radius_handle.radius_config['mode'] == RADIUS_MODE_RELAY:
    #         self._relay_identity_to_radius(_packet.src, username)
    #     else:
    #         self._send_eap_request(EAP_TYPE_PEAP, _packet.src, b'\x01')  # 发起PEAP认证

    # def _handle_auth_response(self, eap, client_mac, session):
    #     """处理认证响应（PEAP/TLS）"""
    #     username = session.get('username', 'unknown')
    #     req = self.radius_handle.create_radius_request(client_mac, username)
    #     req['EAP-Message'] = eap.build()
    #     # 添加状态属性（如果存在）
    #     if session.get('radius_state'):
    #         req['State'] = session['radius_state']
    #     try:
    #         resp = self.radius_handle.client.SendPacket(req)
    #         self._process_radius_response(resp, client_mac)
    #     except Exception as e:
    #         print(f"[RADIUS Error] {str(e)}")
    #         self._send_eap_result(EAP_CODE_FAILURE, client_mac)


    def _relay_identity_to_radius(self, client_mac, username):
        """中继模式发送初始请求"""
        req = self.radius_handle.create_radius_request(client_mac, username)
        req['EAP-Message'] = self._build_eap_message(
            code=EAP_CODE_RESPONSE,
            type=EAP_TYPE_IDENTITY,
            data=username.encode()
        )
        try:
            resp = self.radius_handle.client.SendPacket(req)
            self._process_radius_response(resp, client_mac)
        except Exception as e:
            print(f"[RADIUS Error] {str(e)}")
            self._send_eap_result(EAP_CODE_FAILURE, client_mac)

    def _process_radius_response(self, resp, client_mac):
        """处理RADIUS服务器响应"""
        if resp.code == RADIUS_ACCESS_CHALLENGE:
            print(f"[RADIUS] Challenge for {client_mac}")
            self._update_session(resp, client_mac)
            eap_type, payload = self.radius_handle.handle_radius_challenge(resp, client_mac)
            self._send_eap_request(eap_type, client_mac, payload)
        elif resp.code == RADIUS_ACCESS_ACCEPT:
            print(f"[RADIUS] Access granted for {client_mac}")
            self._send_eap_result(EAP_CODE_SUCCESS, client_mac)
            self._cleanup_session(client_mac)
        elif resp.code == RADIUS_ACCESS_REJECT:
            print(f"[RADIUS] Access denied for {client_mac}")
            self._send_eap_result(EAP_CODE_FAILURE, client_mac)
            self._cleanup_session(client_mac)


    def _cleanup_session(self, client_mac):
        """清理会话"""
        with self.session_lock:
            if client_mac in self.sessions:
                del self.sessions[client_mac]

    def _update_session(self, resp, client_mac):
        with self.session_lock:
            if client_mac in self.sessions:
                self.sessions[client_mac]['radius_state'] = resp.get('State', b'').decode()

    @staticmethod
    def _build_eap_message(code, type, data=b''):
        """构建EAP消息字节流"""
        header = struct.pack('!BBH', code, 0, len(data)+4)
        return header + bytes([type]) + data

    # def handle_eap_response_md5_challenge(self, _packet, session):
    #     self.send_eap_success(_packet)

    # def handle_handshake_request(self, dst_mac):
    #     eap_success = Ether(dst=dst_mac, src=self.mac, type=EAPOL_TYPE_EAP) / EAPOL(version=1, type=0) / EAP(code=EAP_CODE_SUCCESS, id=2)
    #     sendp(eap_success, iface=self.iface, verbose=False)
    #     print("[Server --> Client]: Sent Handshake-Request")

    def _get_next_id(self):
        """生成下一个EAP ID"""
        self.sequence_num = (self.sequence_num + 1) % 256
        return self.sequence_num

    def _sniff_loop(self):
        """数据包捕获循环"""
        sniff_filter = "ether proto 0x888e"
        while self.running:
            sniff(iface=self.iface, prn=self._process_packet, filter=sniff_filter, store=0, timeout=1)

    def _process_packet(self, _packet):
        if _packet.haslayer(EAPOL):
            if _packet[EAPOL].type == EAPOL_TYPE_EAPOL_START:  # EAPOL-Start
                self.handle_eapol_start(_packet)
            elif _packet[EAPOL].type == EAPOL_TYPE_EAP_PACKET:  # EAP-Packet:
                self.handle_eap_packet(_packet)
            else:
                print('unknown eapol type:%s' % _packet[EAPOL].type)

    def start(self):
        """启动认证服务"""
        self.running = True
        sniff_thread = threading.Thread(target=self._sniff_loop)
        sniff_thread.daemon = True
        sniff_thread.start()
        print(f"[Auth] Service started on {self.iface}")


# Example usage
if __name__ == "__main__":
    iface = "以太网"
    config = {
        'server': '192.168.253.141:1812',
        'user': 'operator',
        'password': 'testpass',
        'shared_secret': 'testing123',
        'mode': RADIUS_MODE_RELAY  # 或 RADIUS_MODE_TERMINATE
    }
    server = EAPAuthenticator(iface=iface, radius_config=config)
    try:
        server.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Service stopping...")
        server.running = False
