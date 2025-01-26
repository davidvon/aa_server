import struct

from eap_constants import RADIUS_MODE_TERMINATE
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest


class RadiusHandler:
    def __init__(self,  auth_mac, radius_config):
        self.radius_config = radius_config
        self._init_radius_client()
        self.sequence_num = 0
        self.auth_mac = auth_mac

    def _init_radius_client(self):
        """初始化RADIUS客户端连接"""
        self.client = Client(
            server=self.radius_config['server'],
            authport=self.radius_config.get('port', 1812),
            secret=self.radius_config['secret'].encode(),
            dict=Dictionary("dictionary")
        )
        # 配置NAS属性
        self.nas_ip = self.radius_config.get('nas_ip', '192.168.1.1')
        self.nas_id = self.radius_config.get('nas_id', 'pyradius-auth')

    def create_radius_request(self, client_mac, username):
        """创建基础RADIUS请求"""
        req = self.client.CreateAuthPacket(
            code=AccessRequest
        )
        # 添加标准属性
        req["User-Name"] = username
        req["NAS-IP-Address"] = self.nas_ip
        req["NAS-Identifier"] = self.nas_id
        # req['Called-Station-Id'] = self.auth_mac
        # req['Calling-Station-Id'] = client_mac.replace(':', '-')
        return req

    def handle_radius_challenge(self, resp, client_mac):
        """处理挑战响应"""
        # 解析EAP消息
        eap_data = resp['EAP-Message'][0]
        if len(eap_data) < 5:
            print("[ERROR] Invalid EAP challenge data")
            return

        code, id, length = struct.unpack('!BBH', eap_data[:4])
        eap_type = eap_data[4]
        payload = eap_data[5:] if length > 5 else b''
        return eap_type, payload


    def process_eap(self, eap_pkt, session_state=None):
        """处理EAP消息并返回RADIUS响应"""
        req = self.client.CreateAuthPacket(code=2)  # Access-Request

        # 添加必要属性
        req["User-Name"] = "test_user@domain.com"
        req["NAS-IP-Address"] = "192.168.1.1"
        req["EAP-Message"] = eap_pkt.build()

        if session_state and self.radius_config['mode'] == RADIUS_MODE_TERMINATE:
            req["State"] = session_state

        # 发送请求
        reply = self.client.SendPacket(req)
        return self._parse_radius_reply(reply)


    @staticmethod
    def _parse_radius_reply(reply):
        """解析RADIUS响应"""
        result = {
            "code": reply.code,
            "state": reply.get("State", None),
            "eap_message": reply.get("EAP-Message", None)
        }
        return result