from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPP, PPP_PAP_Request


# MAC 地址 & 认证信息
iface = "ens33"
src_mac = get_if_hwaddr(iface)
dst_mac = get_if_hwaddr(iface)
username, password = "user", "password123"

def create_pap_frame():
    # Ethernet 帧头 (目标 MAC 和 源 MAC 地址, EtherType: 0x880B 表示 PPPoE)
    ether_header = Ether(dst=dst_mac, src=src_mac, type=0x880B)
    #
    # # PPP 帧头
    # # 标识符：0x01, 长度：0x08（用户名 + 密码），协议字段：LCP（0x21）
    # ppp_header = Raw(load=b'\x01\x00\x08\x00\x21')
    #
    # # PAP 数据
    # # 标识符：0x01, 长度：0x08, 用户名 "user" (75 73 65 72 00), 密码 "password123" (70 61 73 73 77 6f 72 64 00)
    # pap_data = Raw(load=b'\x01\x08\x75\x73\x65\x72\x00\x70\x61\x73\x73\x77\x6f\x72\x64\x00')

    ppp = PPP(proto=0xC023)

    # 构造 PAP 请求报文
    username = "user"
    password = "password123"
    pap = PPP_PAP_Request(id=0x01, username=username, password=password)
    print('pap=%s' % pap.build().hex())

    # 组合各层形成完整的报文
    pap_frame = ether_header / ppp / pap

    return pap_frame


# 构造 PAP 请求报文
pap_frame = create_pap_frame()

# 显示构造的报文内容
pap_frame.show()

# 发送报文（可以根据需要选择实际的接口发送报文）
sendp(pap_frame, iface=iface)  # 取消注释并替换为实际接口