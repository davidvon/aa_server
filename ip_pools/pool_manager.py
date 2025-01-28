from threading import Lock
from ip_pools.dhcp_pool import DHCPPool


# ---------------------- 多地址池调度器 ----------------------
class PoolManager:
    def __init__(self):
        self.pools = []  # 每个元素为 (relay_ip, linkselect, pool)
        self.lock = Lock()

    def add_pool(self, relay_ip, linkselect, subnet, start, end):
        """添加地址池及匹配规则"""
        with self.lock:
            self.pools.append({
                "relay_ip": relay_ip,
                "linkselect": linkselect,
                "pool": DHCPPool(subnet, start, end)
            })

    def select_pool(self, addr, relay_ip, linkselect):
        """根据 Relay IP 和 Option 82-5 选择地址池"""
        with self.lock:
            # 优先级：同时匹配 > Relay IP > Link Selection
            for pool_info in self.pools:
                r_match = (pool_info["relay_ip"] == relay_ip) if relay_ip else False
                l_match = (pool_info["linkselect"] == linkselect) if linkselect else False

                if r_match and l_match:
                    return pool_info["pool"]
                elif r_match:
                    return pool_info["pool"]
                elif l_match:
                    return pool_info["pool"]
            return None  # 无匹配池


