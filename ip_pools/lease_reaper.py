import time
import threading


# ---------------------- 租约回收线程 ----------------------
class LeaseReaper(threading.Thread):
    def __init__(self, pool_manager):
        super().__init__(daemon=True)
        self.pool_manager = pool_manager

    def run(self):
        while True:
            time.sleep(60)  # 每分钟清理一次
            for pool_info in self.pool_manager.pools:
                pool = pool_info["pool"]
                expired = [ip for ip, lease in pool.leases.items() if lease["expire"] < time.time()]
                for ip in expired:
                    pool.release_ip(ip)
