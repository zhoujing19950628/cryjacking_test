import psutil
import time
from collections import defaultdict
import tkinter as tk
from threading import Thread
import queue

# 获取总体CPU使用率和每个进程的CPU使用率
def get_process_info():
    """
    计算一秒间隔内的总体CPU使用率和每个进程的CPU使用率。
    返回总体CPU百分比和包含进程信息的列表（PID、父PID、名称、CPU使用率）。
    """
    initial_overall = psutil.cpu_times()
    processes = []
    for p in psutil.process_iter(['pid', 'ppid', 'name']):
        try:
            processes.append({
                'pid': p.info['pid'],
                'ppid': p.info['ppid'],
                'name': p.info['name'],
                'initial_cpu_times': p.cpu_times()
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    time.sleep(1)  # 等待1秒以计算CPU使用率

    final_overall = psutil.cpu_times()

    # 计算总体CPU使用率
    overall_user = final_overall.user - initial_overall.user
    overall_system = final_overall.system - initial_overall.system
    overall_idle = final_overall.idle - initial_overall.idle
    total_time = overall_user + overall_system + overall_idle
    overall_cpu_percent = ((overall_user + overall_system) / total_time) * 100 if total_time > 0 else 0

    # 计算每个进程的CPU使用率
    for proc in processes:
        try:
            p = psutil.Process(proc['pid'])
            current_cpu_times = p.cpu_times()
            user_diff = current_cpu_times.user - proc['initial_cpu_times'].user
            system_diff = current_cpu_times.system - proc['initial_cpu_times'].system
            process_time = user_diff + system_diff
            cpu_percent = (process_time / total_time) * 100 * psutil.cpu_count() if total_time > 0 else 0
            proc['cpu_percent'] = cpu_percent
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc['cpu_percent'] = 0

    return overall_cpu_percent, processes

# 检测异常进程树
def detect_abnormal_process_trees(processes, threshold=100, min_children=3):
    """
    检测异常进程树：父进程的子进程总CPU使用率超过阈值且子进程数量达到最小要求。
    返回异常父进程列表，包含PID、名称、子进程总CPU使用率和子进程数量。
    """
    children_cpu = defaultdict(float)
    children_count = defaultdict(int)
    parent_names = {proc['pid']: proc['name'] for proc in processes}

    for proc in processes:
        ppid = proc['ppid']
        if ppid != 0:
            children_cpu[ppid] += proc['cpu_percent']
            children_count[ppid] += 1

    abnormal_parents = []
    for ppid, total_cpu in children_cpu.items():
        if total_cpu > threshold and children_count[ppid] >= min_children:
            parent_name = parent_names.get(ppid, 'Unknown')
            abnormal_parents.append({
                'pid': ppid,
                'name': parent_name,
                'total_cpu': total_cpu,
                'num_children': children_count[ppid]
            })

    return abnormal_parents

# 后台监控线程函数
def monitor(q):
    """
    持续监控系统指标，每5秒将数据放入队列。
    数据包括总体CPU使用率、异常进程树和模型触发状态。
    """
    while True:
        overall_cpu, processes = get_process_info()
        abnormal_parents = detect_abnormal_process_trees(processes)
        trigger = overall_cpu > 80 and len(abnormal_parents) > 0
        data = {
            'overall_cpu': overall_cpu,
            'abnormal_parents': abnormal_parents,
            'trigger': trigger
        }
        q.put(data)
        time.sleep(5)  # 每5秒检查一次

# 设置GUI
root = tk.Tk()
root.title("挖矿木马检测器")

cpu_label = tk.Label(root, text="总体CPU使用率：")
cpu_label.pack()

abnormal_label = tk.Label(root, text="异常进程树：")
abnormal_label.pack()

abnormal_text = tk.Text(root, height=10, width=50)
abnormal_text.pack()

trigger_label = tk.Label(root, text="模型触发：")
trigger_label.pack()

# 用于线程间通信的队列
q = queue.Queue()

# 启动监控线程
thread = Thread(target=monitor, args=(q,))
thread.daemon = True
thread.start()

# 更新GUI的函数
def update_gui():
    """
    每秒检查队列，更新GUI显示总体CPU使用率、异常进程树和模型触发状态。
    """
    try:
        data = q.get_nowait()
        overall_cpu = data['overall_cpu']
        abnormal_parents = data['abnormal_parents']
        trigger = data['trigger']

        cpu_label.config(text=f"总体CPU使用率：{overall_cpu:.2f}%")

        abnormal_text.delete(1.0, tk.END)
        for parent in abnormal_parents:
            line = f"PID: {parent['pid']}，名称: {parent['name']}，总CPU: {parent['total_cpu']:.2f}%，子进程数: {parent['num_children']}\n"
            abnormal_text.insert(tk.END, line)

        trigger_label.config(text=f"模型触发：{'是' if trigger else '否'}")
    except queue.Empty:
        pass

    root.after(1000, update_gui)  # 每秒更新一次

update_gui()

root.mainloop()