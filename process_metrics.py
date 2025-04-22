import subprocess
import time
import psutil
import threading
import argparse

# 获取/proc/stat中的进程总数
def get_processes():
    with open('/proc/stat', 'r') as f:
        for line in f:
            if line.startswith('processes'):
                return int(line.split()[1])
    return 0

# 获取/proc/meminfo中的内存信息
def get_meminfo():
    meminfo = {}
    with open('/proc/meminfo', 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0].rstrip(':')
                value = int(parts[1])
                meminfo[key] = value
    return meminfo

# 线程：收集cachestat的命中次数
class CacheStatThread(threading.Thread):
    def __init__(self, duration):
        super().__init__()
        self.duration = duration
        self.total_hits = 0

    def run(self):
        try:
            process = subprocess.Popen(['cachestat', '1'], stdout=subprocess.PIPE, text=True)
            start_time = time.time()
            while time.time() - start_time < self.duration:
                line = process.stdout.readline()
                if line:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[0] != 'TIME':
                        hits = int(parts[1])
                        self.total_hits += hits
                else:
                    time.sleep(0.1)
            process.terminate()
        except Exception as e:
            print(f"CacheStatThread错误: {e}")

# 线程：收集biopattern的I/O模式数据
class BioPatternThread(threading.Thread):
    def __init__(self, duration):
        super().__init__()
        self.duration = duration
        self.total_count = 0
        self.total_kbytes = 0
        self.rnd_sum = 0
        self.seq_sum = 0
        self.intervals = 0

    def run(self):
        try:
            process = subprocess.Popen(['biopattern', '1'], stdout=subprocess.PIPE, text=True)
            start_time = time.time()
            while time.time() - start_time < self.duration:
                line = process.stdout.readline()
                if line:
                    parts = line.strip().split()
                    if len(parts) >= 6 and parts[0] != 'TIME':
                        rnd = float(parts[2])
                        seq = float(parts[3])
                        count = int(parts[4])
                        kbytes = int(parts[5])
                        self.total_count += count
                        self.total_kbytes += kbytes
                        self.rnd_sum += rnd
                        self.seq_sum += seq
                        self.intervals += 1
                else:
                    time.sleep(0.1)
            process.terminate()
            if self.intervals > 0:
                self.avg_rnd = self.rnd_sum / self.intervals
                self.avg_seq = self.seq_sum / self.intervals
            else:
                self.avg_rnd = 0
                self.avg_seq = 0
        except Exception as e:
            print(f"BioPatternThread错误: {e}")

# 线程：收集进程的bindsnoop数据
class BindSnoopThread(threading.Thread):
    def __init__(self, pid, duration):
        super().__init__()
        self.pid = pid
        self.duration = duration
        self.tcp_binds = 0
        self.udp_binds = 0

    def run(self):
        try:
            process = subprocess.Popen(['bindsnoop', '-p', str(self.pid)], stdout=subprocess.PIPE, text=True)
            start_time = time.time()
            while time.time() - start_time < self.duration:
                line = process.stdout.readline()
                if line:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        prot = parts[2]
                        if prot == 'TCP':
                            self.tcp_binds += 1
                        elif prot == 'UDP':
                            self.udp_binds += 1
                else:
                    time.sleep(0.1)
            process.terminate()
        except Exception as e:
            print(f"BindSnoopThread错误: {e}")

# 线程：收集进程的新TCP连接数
class TcpConnectThread(threading.Thread):
    def __init__(self, pid, duration):
        super().__init__()
        self.pid = pid
        self.duration = duration
        self.count = 0

    def run(self):
        try:
            process = subprocess.Popen(['tcpconnect', '-p', str(self.pid)], stdout=subprocess.PIPE, text=True)
            start_time = time.time()
            while time.time() - start_time < self.duration:
                line = process.stdout.readline()
                if line:
                    self.count += 1
                else:
                    time.sleep(0.1)
            process.terminate()
        except Exception as e:
            print(f"TcpConnectThread错误: {e}")

def main():
    parser = argparse.ArgumentParser(description="收集进程相关指标")
    parser.add_argument('pid', type=int, help="进程ID")
    parser.add_argument('duration', type=int, help="监控时长（秒）")
    args = parser.parse_args()

    pid = args.pid
    duration = args.duration

    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        print(f"进程 {pid} 不存在。")
        return

    # 启动监控线程
    cachestat_thread = CacheStatThread(duration)
    biopattern_thread = BioPatternThread(duration)
    bindsnoop_thread = BindSnoopThread(pid, duration)
    tcpconnect_thread = TcpConnectThread(pid, duration)

    cachestat_thread.start()
    biopattern_thread.start()
    bindsnoop_thread.start()
    tcpconnect_thread.start()

    # 收集CPU和内存样本
    cpu_idle_samples = []
    ram_used_samples = []
    start_time = time.time()
    start_processes = get_processes()

    while time.time() - start_time < duration:
        cpu_times = psutil.cpu_times_percent(interval=1)
        cpu_idle = cpu_times.idle
        cpu_idle_samples.append(cpu_idle)
        mem = psutil.virtual_memory()
        ram_used = mem.percent
        ram_used_samples.append(ram_used)
        time.sleep(1)

    end_processes = get_processes()

    # 等待线程结束
    cachestat_thread.join()
    biopattern_thread.join()
    bindsnoop_thread.join()
    tcpconnect_thread.join()

    # 收集结果
    cachestat_hits = cachestat_thread.total_hits
    avg_rnd = getattr(biopattern_thread, 'avg_rnd', 0)
    avg_seq = getattr(biopattern_thread, 'avg_seq', 0)
    total_count = biopattern_thread.total_count
    total_kbytes = biopattern_thread.total_kbytes
    tcp_binds = bindsnoop_thread.tcp_binds
    udp_binds = bindsnoop_thread.udp_binds
    new_tcp_connections = tcpconnect_thread.count

    # 计算进程创建速率
    pid_per_sec = (end_processes - start_processes) / duration if duration > 0 else 0

    # 计算平均CPU和内存使用率
    avg_cpu_idle = sum(cpu_idle_samples) / len(cpu_idle_samples) if cpu_idle_samples else 0
    avg_ram_used = sum(ram_used_samples) / len(ram_used_samples) if ram_used_samples else 0

    # 获取缓冲区和缓存内存
    meminfo = get_meminfo()
    buffers_kb = meminfo.get('Buffers', 0)
    cached_kb = meminfo.get('Cached', 0)
    buffers_mb = buffers_kb / 1024
    cached_mb = cached_kb / 1024

    # 映射到所需指标
    metrics = {
        'cachestat_HITS': cachestat_hits,
        'cachestat_BUFFERS(MB)': buffers_mb,
        'cachestat_CACHED(MB)': cached_mb,
        'pidpersec_PID/s': pid_per_sec,
        'biopattern_RND(%)': avg_rnd,
        'biopattern_SEQ(%)': avg_seq,
        'biopattern_COUNT': total_count,
        'biopattern_KBYTES': total_kbytes,
        'cpuunclaimed_CPU(%)': avg_cpu_idle,
        'ramusage_USED(%)': avg_ram_used,
        'tcpstates_NEWSTATE': new_tcp_connections,
        'bindsnoop_PROT_TCP': tcp_binds,
        'bindsnoop_PROT_UDP': udp_binds,
    }

    # 打印指标
    for key in ['cachestat_HITS', 'cachestat_BUFFERS(MB)', 'cachestat_CACHED(MB)', 'pidpersec_PID/s', 'biopattern_RND(%)', 'biopattern_SEQ(%)', 'biopattern_COUNT', 'biopattern_KBYTES', 'cpuunclaimed_CPU(%)', 'ramusage_USED(%)', 'tcpstates_NEWSTATE', 'bindsnoop_PROT_TCP', 'bindsnoop_PROT_UDP']:
        print(f"{key}: {metrics[key]}")

if __name__ == "__main__":
    main()