from pyrad import *
import socket
import pyrad.host
import random

BUFSIZE = 1024
CHALLENGE = "test2"
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

    @staticmethod
    def get_challenge():  # 产生一个4字节的随机挑战码
        challenge = ""
        challenge = challenge + str(chr(random.randint(65, 90)))
        challenge = challenge + str(chr(random.randint(65, 90)))
        challenge = challenge + str(chr(random.randint(65, 90)))
        challenge = challenge + str(chr(random.randint(65, 90)))
        return challenge

    @staticmethod
    def _get_pkt_info(pkt):
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

    def handle_auth_packet(self, pkt):
        global CHALLENGE
        print("Received request:%s" % pkt)
        username = pkt.get('User-Name', [None])[0]
        password = pkt.get('User-Password', [None])[0]
        pkt.secret = self.secret

        if username is None or password is None:
            pkt.dict['Reply-Message'] ='Missing username or password'
            pkt.code = pyrad.packet.AccessReject
        elif username and 'challenge' in username:
            reply = self.CreateAuthPacket(packet=pkt)
            CHALLENGE = self.get_challenge()
            reply.dict['Reply-Message'] = CHALLENGE # 把挑战码发给客户端
            reply.code = packet.AccessChallenge
        elif username in self.users and pkt.PwCrypt(self.users[username]) == password:
            pkt['Reply-Message'] = 'Authentication successful'
            pkt.code = pyrad.packet.AccessAccept
        elif pkt.PwCrypt(CHALLENGE) == password:
            pkt.dict['Reply-Message'] = 'Authentication challenge successful'
            pkt.code = pyrad.packet.AccessAccept
        else:
            pkt.dict['Reply-Message'] = 'Authentication failed'
            pkt.code = pyrad.packet.AccessReject
        return pkt.ReplyPacket()

    def HandleAcctPacket(self, pkt):
        print("Received an accounting request")
        reply = self.CreateReplyPacket(pkt)
        reply.code = pyrad.packet.AccountingResponse
        return reply

    # def get_pkt(self, pkt):
    #     get_pw = None
    #     get_name = None
    #     rad_pkt = self.CreateAuthPacket(packet=pkt)  # 解析请求报文
    #     print("code:", rad_pkt.code)
    #     print("authenticator:", rad_pkt.authenticator)
    #     print("id:", rad_pkt.id)
    #     # rad_pkt.code = packet.AccessChallenge
    #     rad_pkt.secret = self.secret
    #
    #     for key in rad_pkt.keys():
    #         print(key, rad_pkt[key])
    #         if key == "User-Password":
    #             get_pw = 1
    #         if key == "User-Name":
    #             get_name = 1
    #
    #     if 1 == get_pw and 1 == get_name:
    #         self.check_pass(rad_pkt)
    #
    #     reply = rad_pkt.CreateReply()
    #     for key in rad_pkt.keys():
    #         if key == "User-Name":
    #             reply.AddAttribute("User-Name", rad_pkt["User-Name"][0])
    #         if key == "Reply-Message":
    #             reply.AddAttribute("Reply-Message", rad_pkt["Reply-Message"][0])
    #         if key == "NAS-IP-Address":
    #             reply.AddAttribute("NAS-IP-Address", rad_pkt["NAS-IP-Address"][0])
    #         # reply.source = rad_pkt.source
    #         reply.code = rad_pkt.code
    #
    #     return reply.ReplyPacket()

    def _depose_packet(self, radius_server, data, addr):
        try:
            pkt = self.CreateAuthPacket(packet=data)
            reply = self.handle_auth_packet(pkt)
            if reply:
                radius_server.sendto(reply, addr)
        except Exception as e:
            print('Error:%s' % e)


    def start(self):
        radius_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # udp协议
        radius_server.bind(('', RADIUS_DB['auth_port']))

        while True:
            data, client_addr = radius_server.recvfrom(BUFSIZE)
            self._depose_packet(radius_server, data, client_addr)



if __name__ == '__main__':
    srv = RadiusServer()
    srv.start()
