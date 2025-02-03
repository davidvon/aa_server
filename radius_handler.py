from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest
import hashlib
from eap_constants import MODE_RELAY


class RadiusHandler:
    def __init__(self, server, secret, nas_ip, mode=MODE_RELAY):
        self.mode = mode
        self.nas_ip = nas_ip
        self.nas_id = "PyAuthenticator"
        self.client = Client(server=server, secret=secret.encode(), dict=Dictionary("dictionary"))

    def send_request(self, username, eap_data=None):
        """创建基础RADIUS请求包"""
        req = self.client.CreateAuthPacket(code=AccessRequest)
        req.dict.attributes['User-Name'] = username
        req.dict.attributes['NAS-IP-Address'] = self.nas_ip
        req.dict.attributes['NAS-Identifier'] = self.nas_id
        if eap_data:
            req.dict.attributes['EAP-Message'] = eap_data
        self._add_message_auth(req)
        resp = self._send_packet(req)
        return resp

    @staticmethod
    def _add_message_auth(packet):
        """添加Message-Authenticator属性"""
        packet.dict.attributes["Message-Authenticator"] = b'\x00' * 16
        raw_packet = packet.RequestPacket()
        authenticator = hashlib.md5(raw_packet + packet.secret).digest()
        packet.dict.attributes["Message-Authenticator"] = authenticator

    def _send_packet(self, request):
        """处理RADIUS请求"""
        try:
            print(f"[RADIUS] request starting: {request.__str__()}")
            return self.client.SendPacket(request)
        except Exception as e:
            print(f"[RADIUS] Error:", e)
            return None
