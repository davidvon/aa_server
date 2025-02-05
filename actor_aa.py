import struct
import time

from pyrad import *
import socket
import pyrad.host
import random

from pyrad.packet import AccessRequest

BUFSIZE = 1024
RADIUS_DB = {
    'auth_port': 1812,
    'secret': b'testing123',
    'users': {'operator':'testpass',
              'bob':'hello'}
}

class RadiusServer(server.Server):
    def __init__(self):
        radius_dict = pyrad.dictionary.Dictionary("handlers/dictionary.rfc2865")  # 从freeradius中搞一个通用的字典使用
        pyrad.host.Host.__init__(self, dict=radius_dict)
        self.secret = RADIUS_DB['secret']
        self.auth_port = RADIUS_DB['auth_port']
        self.users = RADIUS_DB['users']
        self.sessions = {}
        self.running = True

    def _verify_user_auth(self, pkt, username):
        if 'State' in pkt:
            print("Sending Access-Challenge for multi-factor authentication")
            pkt['Reply-Message'] = 'Please enter your OTP'
            pkt['State'] = pkt['State']  # 保持状态
            pkt.code = pyrad.packet.AccessChallenge
        else:
            # 返回 Access-Accept
            pkt['Reply-Message'] = 'Authentication successful',
            pkt['Session-Timeout'] = 100
            pkt.code = pyrad.packet.AccessAccept
            self.sessions[username] = {'start_time': time.time()}
        return pkt

    def _handle_auth_packet(self, data):
        pkt = self.CreateAuthPacket(packet=data)
        print("Received request:%s" % pkt)
        username = pkt.get('User-Name', [None])[0]
        password = pkt.get('User-Password', [None])[0]
        pkt.secret = self.secret

        pkt.code = pyrad.packet.AccessReject
        pkt['Reply-Message'] = 'Authentication failed'
        try:
            if username is None or password is None:
                pkt['Reply-Message'] ='Missing username or password'
            elif username in self.users and pkt.PwCrypt(self.users[username]) == password:
                pkt = self._verify_user_auth(pkt, username)
        except Exception as e:
            print('[Radius] exception:%s' % e)
        return pkt.ReplyPacket()

    def _handle_packet(self, radius_server, data, addr):
        try:
            self.code = struct.unpack('!B', data[0:1])[0]
            if self.code == AccessRequest:
                reply = self._handle_auth_packet(data)
            else:
                print('[Radius] Not support code:%s' % self.code)
                return
            if reply:
                radius_server.sendto(reply, addr)
        except Exception as e:
            print('Error:%s' % e)

    def start(self):
        radius_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # udp协议
        radius_server.bind(('', RADIUS_DB['auth_port']))

        while self.running:
            data, client_addr = radius_server.recvfrom(BUFSIZE)
            self._handle_packet(radius_server, data, client_addr)



if __name__ == '__main__':
    srv = RadiusServer()
    srv.start()
    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.running = False
