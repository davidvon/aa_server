import time
from threading import Lock
from ip_pools.utils import generate_ip_range


# ---------------------- DHCP 地址池管理 ----------------------
class DHCPPool:
    def __init__(self, subnet, start_ip, end_ip):
        self.subnet = subnet
        self.dynamic_ips = set(generate_ip_range(start_ip, end_ip))  # 可用动态 IP
        self.leases = {}  # {ip: {"mac": str, "expire": float}}
        self.static_leases = {}  # {mac: ip} 静态绑定
        self.mac_history = {}  # {mac: ip} 动态分配历史记录
        self.lock = Lock()  # 线程安全锁

    def allocate_ip(self, mac):
        """为 MAC 地址分配 IP（优先复用历史记录）"""
        with self.lock:
            # 1. 检查静态绑定
            if mac in self.static_leases:
                return self.static_leases[mac]

            # 2. 检查历史分配且 IP 可用
            if mac in self.mac_history:
                history_ip = self.mac_history[mac]
                if history_ip in self.dynamic_ips:
                    self.dynamic_ips.remove(history_ip)
                    self.leases[history_ip] = {"mac": mac, "expire": time.time() + 3600}
                    return history_ip

            # 3. 分配新 IP
            if not self.dynamic_ips:
                return None  # 地址池耗尽
            new_ip = self.dynamic_ips.pop()
            self.leases[new_ip] = {"mac": mac, "expire": time.time() + 3600}
            self.mac_history[mac] = new_ip
            return new_ip

    def release_ip(self, ip):
        """释放 IP 回地址池"""
        with self.lock:
            if ip in self.leases:
                del self.leases[ip]
                self.dynamic_ips.add(ip)
