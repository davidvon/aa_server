from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPP, PPPoE

# PAP 常量定义
PAP_AUTH_PROTO = 0xC023

AUTHENTICATE_REQUEST = 1
AUTHENTICATE_ACK = 2
AUTHENTICATE_NAK = 3

# 发送 PAP 认证请求
def send_pap_auth():
    pap_length = 1 + 1 + 2 + (1 + len(username.encode())) + (1 + len(password.encode()))
    pap_payload = struct.pack(
        f"!BBH B{len(username)}s B{len(password)}s",
        request_code,  # Code: 1 (Authenticate-Request)
        identifier,
        pap_length,  # 长度字段，占 2 字节
        len(username), username.encode(),
        len(password), password.encode()
    )
    pap_request_pkt = Ether(src=src_mac, dst=dst_mac) / PPPoE(sessionid=session_id) / PPP(proto=PAP_AUTH_PROTO) / Raw(load=pap_payload)
    print("Sending PAP Authentication Request")
    pap_request_pkt.show()
    sendp(pap_request_pkt, iface=iface)

# 处理 PAP 认证应答
def handle_pap_response(pkt):
    if PPP in pkt and pkt[PPP].proto == PAP_AUTH_PROTO:
        print("Received PAP Response")
        if pkt.load[0] == 2:
            print("PAP Authentication Successful")
        else:
            print("PAP Authentication Failed")


if __name__ == '__main__':
    iface = "ens33"
    username, password = "user", "password123"
    request_code = AUTHENTICATE_REQUEST
    identifier = 0x02
    session_id = 0x03
    src_mac = get_if_hwaddr(iface)  ### 需要修改 ###
    dst_mac = get_if_hwaddr(iface)
    print("client.mac=%s, server.mac=%s" % (src_mac, dst_mac))

    # 发送 PAP 认证请求
    send_pap_auth()

    # 监听 PAP 认证应答
    print("Sniffing for PAP Response packets...")
    sniff(iface=iface, filter=f"ether proto {hex(PAP_AUTH_PROTO)}", prn=handle_pap_response)
