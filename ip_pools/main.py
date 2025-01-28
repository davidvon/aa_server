from ip_pools.dhcp_server import DHCPServer
from ip_pools.lease_reaper import LeaseReaper
from ip_pools.pool_manager import PoolManager


# ---------------------- 初始化测试 ----------------------
if __name__ == "__main__":
    # 初始化地址池管理器
    manager = PoolManager()

    # 添加多个地址池规则
    manager.add_pool(
        relay_ip="10.1.1.1",  # 支持按Relay-Agent-IP字段匹配
        linkselect=None,
        subnet="10.1.1.0/24",
        start="10.1.1.100",
        end="10.1.1.200"
    )

    manager.add_pool(
        relay_ip=None,
        linkselect="10.2.2.1",  # 支持按DHCP option 82-5的linkselection字段匹配
        subnet="10.2.2.0/24",
        start="10.2.2.100",
        end="10.2.2.200"
    )

    # 启动租约回收
    LeaseReaper(manager).start()

    # 启动DHCP服务器
    server = DHCPServer(manager)
    server.run()
