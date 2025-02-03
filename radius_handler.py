import hmac

from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AccessAccept
import hashlib


class RadiusHandler:
    def __init__(self, config):
        self.server = config['server']
        self.auth_port = 1812
        self.username =config['username']
        self.password = config['password']
        self.mode = config['mode']
        self.secret = config['secret']
        self.dict_file = "dictionary"
        self.timeout = 5
        self.client = Client(server=self.server, authport=self.auth_port, secret=self.secret.encode(),
                             dict=Dictionary(self.dict_file), timeout=self.timeout)

    def send_request(self, eap_data=None):
        """创建基础RADIUS请求包"""
        request = self.client.CreateAuthPacket(code=AccessRequest)
        request['User-Name'] =  self.username
        request['User-Password'] = request.PwCrypt(self.password)
        if eap_data:
            request['EAP-Message'] = eap_data
        # self._add_message_auth(request)
        resp = self._send_packet(request)
        return resp

    def _add_message_auth(self, request):
        """添加Message-Authenticator属性"""
        request.dict.attributes["Message-Authenticator"] = b'\x00' * 16
        raw_packet = request.RequestPacket()
        request.authenticator = hashlib.md5(raw_packet + request.secret).digest()
        raw_packet2 = request.RequestPacket()
        hmac_md5 = hmac.new(self.secret.encode(), raw_packet2, hashlib.md5).digest()
        request.dict.attributes["Message-Authenticator"] = hmac_md5

    def _send_packet(self, request):
        """处理RADIUS请求"""
        try:
            print(f"[Server --> RadiusService] Request Starting:{request}")
            reply = self.client.SendPacket(request)
            print("[RADIUS] Auth:", 'Success' if reply.code == AccessAccept else 'Failure(%d)' % reply.code)
            return reply
        except Exception as e:
            print(f"[RADIUS] Error:", e)

