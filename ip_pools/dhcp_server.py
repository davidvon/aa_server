import socket


# ---------------------- DHCP 服务器核心 ----------------------
class DHCPServer:
    def __init__(self, pool_manager):
        self.pool_manager = pool_manager
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", 67))  # DHCP 标准端口

    def parse_dhcp_packet(self, data):
        """解析 DHCP 数据包关键字段"""
        # 解析 giaddr (Relay Agent IP)
        giaddr = data[24:28]
        relay_agent_ip = socket.inet_ntoa(giaddr) if giaddr != b'\x00\x00\x00\x00' else None

        # 解析 MAC 地址 (chaddr 字段前6字节)
        mac = ":".join(f"{b:02x}" for b in data[28:34])

        # 解析 DHCP 选项
        options = data[240:]
        msg_type = None
        link_selection = None

        i = 0
        while i < len(options):
            code = options[i]
            if code == 255:  # END
                break
            length = options[i + 1]
            value = options[i + 2:i + 2 + length]

            if code == 53:  # DHCP Message Type
                msg_type = self.parse_message_type(value)
            elif code == 82:  # Option 82
                link_selection = self.parse_option82(value)

            i += 2 + length

        return {
            "relay_agent_ip": relay_agent_ip,
            "link_selection": link_selection,
            "mac": mac,
            "msg_type": msg_type
        }

    def parse_message_type(self, value):
        """解析 DHCP 消息类型"""
        types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK"}
        return types.get(value[0], "UNKNOWN")

    def parse_option82(self, value):
        """解析 Option 82 的 Link Selection 子选项"""
        j = 0
        while j < len(value):
            sub_code = value[j]
            sub_len = value[j + 1]
            sub_val = value[j + 2:j + 2 + sub_len]
            j += 2 + sub_len
            if sub_code == 5 and sub_len == 4:  # Link Selection
                return socket.inet_ntoa(sub_val)
        return None

    def send_response(self, packet, ip, mac):
        """构造 DHCP OFFER/ACK 响应包（简化版）"""
        # 这里需要根据协议标准构造完整响应，以下为示意逻辑
        resp = bytearray(1024)
        resp[0:4] = b'\x02'
        resp[28:34] = bytes.frommac(mac.replace(":", ""))  # chaddr
        resp[16:20] = socket.inet_aton(ip)  # yiaddr
        # ... 其他必要字段填充
        self.sock.sendto(resp, ("255.255.255.255", 68))

    def run(self):
        """主事件循环"""
        while True:
            data, addr = self.sock.recvfrom(1024)
            fields = self.parse_dhcp_packet(data)

            # 选择地址池
            pool = self.pool_manager.select_pool(addr, fields["relay_agent_ip"], fields["link_selection"])
            if not pool:
                continue

            # 处理 DISCOVER 请求
            if fields["msg_type"] == "DISCOVER":
                allocated_ip = pool.allocate_ip(fields["mac"])
                if allocated_ip:
                    self.send_response(data, allocated_ip, fields["mac"])
