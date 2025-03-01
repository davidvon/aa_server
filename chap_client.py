from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPP, PPPoE
from scapy.all import *
import random
import hashlib

# CHAP 常量
PPP_CHAP_PROTO = 0xC223  # CHAP 协议
CHAP_CHALLENGE = 1        # CHAP 挑战报文类型
CHAP_RESPONSE = 2         # CHAP 响应报文类型
CHAP_SUCCESS = 3          # CHAP 认证成功
CHAP_FAILURE = 4          # CHAP 认证失败

# 发送 CHAP 挑战
def send_chap_challenge():
    code = CHAP_CHALLENGE
    challenge_value = random.randbytes(16)  # 生成 16 字节的随机挑战值
    chap_length = 1 + 1 + 2 + (1 + len(challenge_value)) + len(username)
    payload = struct.pack(
        f"!BBH B{len(challenge_value)}s",
        code,
        identifier,
        chap_length,
        len(challenge_value), challenge_value
    ) + username.encode()

    chap_challenge_pkt = (Ether(src=server_mac, dst=client_mac) /
                          PPPoE(sessionid=session_id) /
                          PPP(proto=PPP_CHAP_PROTO) /
                          Raw(load=payload))
    print(f"Sending CHAP Challenge (ID={identifier}, Challenge={challenge_value.hex()})")
    sendp(chap_challenge_pkt, iface=iface)

def generate_chap_response(identifier, challenge, password):
    return hashlib.md5(bytes([identifier]) + password.encode() + challenge).digest()


def handle_chap_challenge(packet):
    if PPP in packet and packet[PPP].proto == PPP_CHAP_PROTO:
        print("Received CHAP packet")
        payload = bytes(packet[PPP])[2:]
        if payload[0] == 1:  # CHAP Challenge
            identifier = payload[1]
            length = int.from_bytes(payload[2:4], byteorder="big")
            value_size = payload[4]
            challenge = payload[5:5 + value_size]
            response = generate_chap_response(identifier, challenge, password)

            code = CHAP_RESPONSE
            chap_length =1 + 1 + 2 + (1 + len(response)) + len(username)
            payload = struct.pack(
                f"!BBH B{len(response)}s",
                code,
                identifier,
                chap_length,
                len(response), response
            ) + username.encode()
            chap_response_pkt = (Ether(src=server_mac, dst=client_mac) /
                                 PPPoE(sessionid=session_id) /
                                 PPP(proto=PPP_CHAP_PROTO) /
                                 Raw(load=payload))
            print("Sending CHAP Response")
            sendp(chap_response_pkt, iface=iface)


def sniff_loop():
    sniff(iface=iface, prn=handle_chap_challenge, timeout=10)


if __name__ == '__main__':
    # MAC 地址 & 认证信息
    iface = "ens33"
    username, password = "user", "password123"
    identifier = 0x02
    session_id = 0x03
    server_mac = get_if_hwaddr(iface)  ### 需要修改 ###
    client_mac = get_if_hwaddr(iface)
    print("client.mac=%s, server.mac=%s" % (server_mac, client_mac))

    print("Sniffing for CHAP Challenge packets...")
    Thread(target=sniff_loop, daemon=True).start()
    time.sleep(1)

    # 本地测试，交换机设备上不用执行下面命令
    send_chap_challenge()

    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        exit(0)
