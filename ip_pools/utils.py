import socket
import struct

# ---------------------- IP 工具函数 ----------------------
def ip_to_int(ip):
    """将 IPv4 字符串转换为整数"""
    return struct.unpack('!I', socket.inet_aton(ip))[0]


def int_to_ip(num):
    """将整数转换为 IPv4 字符串"""
    return socket.inet_ntoa(struct.pack('!I', num))


def generate_ip_range(start_ip, end_ip):
    """生成 IP 地址范围列表"""
    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    return [int_to_ip(ip) for ip in range(start, end + 1)]

