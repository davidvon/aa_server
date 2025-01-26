from pyrad.client import Client
from pyrad.dictionary import Dictionary
from eap_constants import *


class RadiusHandler:
    def __init__(self, server, secret, mode=RADIUS_MODE_RELAY):
        self.client = Client(server=server, secret=secret.encode(), dict=Dictionary("dictionary"))
        self.mode = mode  # 中继模式或终结模式

    def process_eap(self, eap_pkt, session_state=None):
        """处理EAP消息并返回RADIUS响应"""
        req = self.client.CreateAuthPacket(code=2)  # Access-Request

        # 添加必要属性
        req["User-Name"] = "test_user@domain.com"
        req["NAS-IP-Address"] = "192.168.1.1"
        req["EAP-Message"] = eap_pkt.build()

        if session_state and self.mode == RADIUS_MODE_TERMINATE:
            req["State"] = session_state

        # 发送请求
        reply = self.client.SendPacket(req)
        return self._parse_radius_reply(reply)

    def _parse_radius_reply(self, reply):
        """解析RADIUS响应"""
        result = {
            "code": reply.code,
            "state": reply.get("State", None),
            "eap_message": reply.get("EAP-Message", None)
        }
        return result
