import hashlib
import platform
import struct
import time

from pyrad import *
import socket
import pyrad.host
import random

from pyrad.packet import AccessRequest, AccountingRequest, CoARequest

from constants import STATE_START, STATE_INTERIM_UPDATE, STATE_ACCOUNTING_ON, STATE_ACCOUNTING_OFF, STATE_STOP

BUFSIZE = 1024
RADIUS_DB = {
    'auth_port': 1812,
    'secret': b'testing123',
    'users': {'operator':'testpass',
              'bob':'hello'},
    'nas':[]
}

class RadiusServer(server.Server):
    def __init__(self):
        radius_dict = pyrad.dictionary.Dictionary("handlers/dictionary")  # 从freeradius中搞一个通用的字典使用
        pyrad.host.Host.__init__(self, dict=radius_dict)
        self.secret = RADIUS_DB['secret']
        self.auth_port = RADIUS_DB['auth_port']
        self.users = RADIUS_DB['users']
        self.sessions = {}
        self.running = True

    def HandleAuthPacket(self, pkt):
        print("Received request:%s" % pkt)
        username = pkt.get('User-Name', [None])[0]
        pwd = pkt.get('User-Password', [None])[0]
        chap_pwd = pkt.get('CHAP-Password', [None])[0]
        chap_challenge = pkt.get('CHAP-Challenge', [None])[0]
        pkt.secret = self.secret

        pkt.code = pyrad.packet.AccessReject
        try:
            if username is None or (pwd is None and chap_pwd is None):
                pkt['Reply-Message'] ='Missing username or password or chap-password'
            elif username in self.users:
                if pwd is not None and pkt.PwCrypt(self.users[username]) == pwd:
                    print("User[%s]: Authentication successful" % username)
                    if 'State' in pkt:
                        pkt['Reply-Message'] = 'Please enter your OTP'
                        pkt['State'] = pkt['State']  # 保持状态
                        pkt.code = pyrad.packet.AccessChallenge
                        print("User[%s]: Sending Access-Challenge for multi-factor authentication" % username)
                    else:
                        # 返回 Access-Accept
                        pkt['Reply-Message'] = 'Authentication successful',
                        pkt['Session-Timeout'] = 100
                        pkt.code = pyrad.packet.AccessAccept
                        self.sessions[username] = {'start_time': time.time()}
                        print("User[%s]: Authentication successful" % username)
                elif username in self.users and chap_pwd is not None and chap_challenge is not None:
                    identifier, actual_chap_pwd = chap_pwd[0], chap_pwd[1:]
                    # 计算期望的 CHAP-Password
                    expected_chap_pwd = hashlib.md5(bytes([identifier]) + self.users[username].encode() + chap_challenge).digest()
                    if expected_chap_pwd == actual_chap_pwd:
                        pkt['Reply-Message'] = 'Authentication successful',
                        pkt['Session-Timeout'] = 100
                        pkt.code = pyrad.packet.AccessAccept
                        self.sessions[username] = {'start_time': time.time()}
                        print("User[%s]: CHAP-Authentication successful" % username)
                    else:
                        pkt['Reply-Message'] = 'Authentication failed'
                        print("User[%s]: CHAP-Authentication failure" % username)
            else:
                pkt['Reply-Message'] = 'Authentication failed'
                print("User[%s]: Authentication failure" % username)
        except Exception as e:
            print('[Radius] exception:%s' % e)
        return pkt

    def HandleAcctPacket(self, pkt):
        print("Received Accounting-Request")
        required_attributes = ["NAS-IP-Address", "Acct-Status-Type", "User-Name"]
        for attr in required_attributes:
            if attr not in pkt:
                print(f"Missing required attribute: {attr}")
                return
        username = pkt['User-Name'][0]
        acct_status_type = pkt['Acct-Status-Type'][0]
        nas_ip = pkt["NAS-IP-Address"][0]

        if username and acct_status_type:
            if acct_status_type == STATE_START:
                print(f"Accounting start for user {username}")
                self.sessions[username] = {'start_time': time.time()}
            elif acct_status_type == STATE_STOP:
                print(f"Accounting stop for user {username}")
                if username in self.sessions:
                    session_duration = time.time()- self.sessions[username]['start_time']
                    print(f"Session duration for {username}: {session_duration} seconds")
                    del self.sessions[username]
            elif acct_status_type == STATE_INTERIM_UPDATE:
                print(f"Accounting update time for user {username}")
                self.sessions[username] = {'start_time': time.time()}
            elif acct_status_type == STATE_ACCOUNTING_ON:
                print(f"NAS[%s] WORK ON" % nas_ip)
            elif acct_status_type == STATE_ACCOUNTING_OFF:
                print(f"NAS[%s] WORK OFF" % nas_ip)
        pkt.code = pyrad.packet.AccountingResponse
        return pkt

    def HandleCoaPacket(self, pkt):
        print("Received CoA-Request")
        username = pkt.get('User-Name', [None])[0]
        coa_action = pkt.get('CoA-Request-Type', [None])[0]

        if username and coa_action:
            if coa_action == 'Disconnect':
                print(f"Disconnecting user {username}")
                if username in self.sessions:
                    del self.sessions[username]
                    reply = self.CreateReplyPacket(pkt, **{
                        'Reply-Message': 'User disconnected successfully'
                    })
                    reply.code = pyrad.packet.CoAACK
                else:
                    reply = self.CreateReplyPacket(pkt, **{
                        'Reply-Message': 'User not found'
                    })
                    reply.code = pyrad.packet.CoANAK
            else:
                reply = self.CreateReplyPacket(pkt, **{
                    'Reply-Message': 'Unsupported CoA action'
                })
                reply.code = pyrad.packet.CoANAK
        else:
            reply = self.CreateReplyPacket(pkt, **{
                'Reply-Message': 'Invalid CoA request'
            })
            reply.code = pyrad.packet.CoANAK

        return pkt


    def _handle_packet(self, radius_server, data, addr):
        try:
            pkt = self.CreateAuthPacket(packet=data)
            self.code = struct.unpack('!B', data[0:1])[0]
            if self.code == AccessRequest:
                pkt = self.HandleAuthPacket(pkt)
            elif self.code == AccountingRequest:
                pkt = self.HandleAcctPacket(pkt)
            elif self.code == CoARequest:
                pkt = self.HandleCoaPacket(pkt)
            else:
                print('[Radius] Not support code:%s' % self.code)
                return
            if pkt:
                reply = pkt.ReplyPacket()
                radius_server.sendto(reply, addr)
        except Exception as e:
            print('Error:%s' % e)

    def start(self):
        print("Starting AA(RADIUS) server...")
        if platform.system().lower() == 'windows':
            radius_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # udp协议
            radius_server.bind(('', RADIUS_DB['auth_port']))
            try:
                while self.running:
                    data, client_addr = radius_server.recvfrom(BUFSIZE)
                    self._handle_packet(radius_server, data, client_addr)
            except KeyboardInterrupt:
                self.running = False
                print("Shutting down RADIUS server...")
        else:
            try:
                server.Run()
            except KeyboardInterrupt:
                print("Shutting down RADIUS server...")


if __name__ == '__main__':
    srv = RadiusServer()
    srv.start()

