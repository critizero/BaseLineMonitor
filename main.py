import os
import re
import json
import logging
import socket

import paramiko
import threading
import subprocess
import time

import ast

import uuid
from producer import *
import shutil


def create_dir(dir):
    if not os.path.exists(dir):
        os.makedirs(dir)


neko = threading.Lock()
LOCAL_IP = '10.26.81.7'
VMEARE_FUZZER_IP = "172.16.239.128"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
DEFAULT_TARGET_IP = "10.0.2.99"


class NDFuzzMonitor:
    def __init__(self, message=None, debug=False):
        # print(message)
        # print(message["params"])
        self.message = message
        # self.protocols = message["params"]["protocol"]
        self.protocols = []
        self.local_ip = LOCAL_IP
        self.thread_info = {}

        self.logger = logging.getLogger(message["params"]["vendor"])
        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(formatter)
        self.logger.addHandler(console)
        self.logger.setLevel(logging.DEBUG)

        with open('config.json', 'r') as conf_f:
            self.config = json.load(conf_f)

        # 一个 vendor 启一个 monitor
        for protocol in self.config[message["params"]["vendor"]]:
            self.protocols.append(protocol)

        self.is_debug = debug

        self._data = []
        self._error = ""
        self._success = True

    def start(self):
        for protocol in self.protocols:
            self.info("======Deliver Task : {} {}======".format(self.message["params"]["vendor"], protocol))
            tmp_link = {
                "vendor": self.message["params"]["vendor"],
                "protocol": protocol,
                "time_limit": self.message["params"]["time_limit"],
                "time_gap": self.message["params"]["time_gap"]
            }
            t_runner = threading.Thread(target=self.run, args=(tmp_link,), daemon=True)
            t_runner.start()

        sec = 0
        while sec < self.message["params"]["time_limit"]:
            time.sleep(1)
            sec += 1

            if sec % self.message["params"]["time_gap"] == 0:
                t_scan = threading.Thread(target=self.run_scan())
                t_scan.start()

    def info(self, info_msg):
        self.logger.debug("\033[94m<MAIN> | {}\033[0m".format(info_msg))

    def run_qemu_image(self, msg): 
        runner = NDFuzzController(message=msg, config=self.config, logger=self.logger)
        runner.start()

    def run_vmware_image(self, msg):
        runner = BlackBoxFuzzController(message=msg, config=self.config, logger=self.logger)
        runner.start()

    def run(self, msg):
        # 初始化配置和结果文件
        config = self.config[msg["vendor"]][msg["protocol"]]
        out_path = "{}/out_{}_{}_BY_BLM".format(config["fuzzer"], msg["vendor"], msg["protocol"])

        res_pre = "log/{}_{}_pre.txt".format(msg["vendor"], msg["protocol"])
        with open(res_pre, "a+") as res_pre_f:
            res_pre_f.truncate(0)

        # 删除结果文件夹
        result_dir = "result-{}-{}".format(msg["vendor"], msg["protocol"])        
        if os.path.exists(result_dir):
            shutil.rmtree(result_dir)

        port = 22
        if config["image_type"] == "qemu":
            with open(config["image_start"], "r") as start_f:
                for line in start_f.readlines():
                    if "-:22 -net nic" in line:
                        port = int(re.findall(r':(\d+)-:22', line)[0])
                        break
        
        target_ip = DEFAULT_TARGET_IP
        if "target_ip" in config:
            target_ip = config["target_ip"]
        
        fuzzer_ip = LOCAL_IP
        if config["image_type"] == "vmware":
            fuzzer_ip = VMEARE_FUZZER_IP

        # 记录结果文件的路径信息
        info = {
            "path": out_path,
            "file": res_pre,
            "config": "{}/Configs/{}.config".format(config["fuzzer"], config["config"]),
            "cv_file": "coverage.txt", 
            "local_result": "result-{}-{}".format(msg["vendor"], msg["protocol"]), 
            "port": port,
            "target_ip": target_ip,
            "fuzzer_ip": fuzzer_ip, 
            "image_type": config["image_type"]
        }

        # 记录当前 fuzz 流程的结果路径信息（看起来好像没啥用）
        neko.acquire()
        self.thread_info[msg["protocol"]] = info
        neko.release()
        
        # 启动 vmware 镜像（新流程）
        if config["image_type"] == "vmware":
            self.run_vmware_image(msg)
        # 启动 qemu 镜像（原流程）
        elif config["image_type"] == "qemu":
            self.run_qemu_image(msg)
        else:
            # 错误的镜像类型
            self.info('[+] Unsupported image type!')

    def get_link(self, fuzzer_ip, port):
        self.info("[+] Link {}:{} via SSH...".format(fuzzer_ip, port))
        retry_count = 5
        transport = None
        while True:
            try:
                transport = paramiko.Transport((fuzzer_ip, port))
                transport.connect(username="nfvfuzzer", password="mima1234")
            except Exception:
                if not retry_count:
                    return None
                time.sleep(10)
                retry_count -= 1
                continue
            break
        return transport

    def run_scan(self):
        self._data = []
        self.info("=======SCANNING RESULT======")
        for protocol in self.protocols:
            t_scanner = threading.Thread(target=self.get_result, args=(self.thread_info[protocol], protocol))
            t_scanner.start()
            t_scanner.join()

        # data = {"keys": keys, "data": self._data}
        data = { "items" : self._data }
        producer_message = self.generate_producer_message(data)

        self.info("Return Message : {}".format(producer_message))

        if self._data:
            producer = TaskQueue()
            producer.send_task_result(producer_message)

    def get_result(self, info, protocol):
        scan_link = self.get_link(info["fuzzer_ip"], info["port"])

        ssh = paramiko.SSHClient()
        ssh._transport = scan_link

        # 获取 ndfuzz 的覆盖率信息
        if "coverage" not in info and info["image_type"] == "qemu":
            stdin, stdout, stderr = ssh.exec_command("cat {}".format(info["config"]))
            res = stdout.read().decode().strip()
            time.sleep(1)
            basic_block_coverage_path = ""
            for line in res.split("\n"):
                if "basic_block_coverage_path" in line:
                    basic_block_coverage_path = re.findall(r"basic_block_coverage_path = (.*)", line)[0]
                    break
            self.info("<{}> | Coverage File at: {}".format(protocol, basic_block_coverage_path))
            info["coverage"] = basic_block_coverage_path

            neko.acquire()
            self.thread_info[protocol]["coverage"] = basic_block_coverage_path
            neko.release()

        stdin, stdout, stderr = ssh.exec_command("ls {}/crashes".format(info["path"]))
        res = stdout.read().decode().strip()
        time.sleep(1)

        pre = []
        res_list = res.split('\n')
        with open(info["file"], "r") as pre_res:
            for line in pre_res.readlines():
                pre.append(line.strip())

        new_list = []
        for file in res_list:
            if file == '':
                continue
            if file not in pre:
                new_list.append(file)

        sftp = paramiko.SFTPClient.from_transport(scan_link)

        with open(info["file"], "a") as pre_res:
            for name in new_list:
                sftp.get("{}/crashes/{}".format(info["path"], name), "{}/{}".format(info["local_result"], name))
                pre_res.write(name + "\n")

        if info["image_type"] == "qemu":
            sftp.get("{}/nfv_coverage".format(info["coverage"]), "{}/{}".format(info["local_result"], info["cv_file"]))

        # stdin, stdout, stderr = ssh.exec_command("tail -n 2 {} | head -n 1".format(self.coverage))
        # coverage = stdout.read().decode().strip()

        if not self.is_debug and new_list:
            successed, error, data = self.get_result_data(info["local_result"], new_list, protocol)

            if not successed:
                self._error += error + '\n'
                self._success = False

            self._data.extend(data)
            
    def generate_producer_message(self, data):
        import copy
        message = self.message

        message["msg_id"] = str(uuid.uuid4())
        message["msg_type"] = 2
        message["destination"] = copy.deepcopy(message["source"])
        message['source'] = '07b8e7db09904e68a08bd6047246ee06'
        message["successed"] = self._success
        message["error"] = self._error
        message["data_uri"] = "null"
        message["data"] = data
        message["timestamp"] = int(time.time())
        message["signature"] = "null"

        return message

    def get_result_data(self, local_result, new_list, protocol):
        value_list = []
        for case_name in new_list:
            with open("{}/{}".format(local_result, case_name), "r") as case_f:
                content = case_f.readline()
                payload_msg_type = ast.literal_eval(content)[0]
                payload = ast.literal_eval(content)[-1]
                result = {
                    "vendor": self.message["params"]["vendor"], 
                    "protocol": protocol,
                    "message_type": payload_msg_type,
                    "payload": payload
                }
                value_list.append(result)
        
        # result = {"items": value_list}
        result = value_list
        # print(value_list)
        successed = True
        error = "null"
        return successed, error, result

class BaseFuzzController:
    def __init__(self, message=None, run_local=False, config=None, logger=None):
        self.local_ip = LOCAL_IP

        if not config:
            with open('config.json', 'r') as conf_f:
                self.config = json.load(conf_f)
        else:
            self.config = config

        self.logger = logger

        self.run_in_local = run_local
        self.debug_message = False

        if message and not self.debug_message:
            self.vendor = message["vendor"]
            self.protocol = message["protocol"]
            self.time_limit = message["time_limit"]
            self.time_gap = message["time_gap"]
        else:
            # for local test
            self.vendor = "srx"
            self.protocol = "snmp"
            self.time_limit = 300
            self.time_gap = 60

        self.res_pre = None
        self.coverage = None
        self.local_result = None

        self.start_fuzzer_flag = False

        self.message = message

        self.out_path = "{}/out_{}_{}_BY_BLM".format(config[self.vendor][self.protocol]["fuzzer"], self.vendor, self.protocol)
        self.info("[!] Output file path : {}".format(self.out_path))

        # 本地结果
        self.res_pre = "log/{}_{}_pre.txt".format(self.vendor, self.protocol)
        with open(self.res_pre, "a+") as res_pre:
            res_pre.truncate(0)
        
        self.local_result = "result-{}-{}".format(self.vendor, self.protocol)
        if os.path.exists(self.local_result):
            shutil.rmtree(self.local_result)

        create_dir("log")
        create_dir(self.local_result)

    def error(self, error_msg):
        self.logger.error("\033[91m<{} {}> | {}\033[0m".format(self.vendor, self.protocol, error_msg))
        exit(0)

    def debug(self, debug_msg):
        self.logger.debug("\033[93m<{} {}> | {}\033[0m".format(self.vendor, self.protocol, debug_msg))

    def info(self, info_msg):
        self.logger.info("\033[92m<{} {}> | {}\033[0m".format(self.vendor, self.protocol, info_msg))

    def start_link(self, fuzzer_ip, port=22):
        self.debug("[+] Link {}:{} via SSH...".format(fuzzer_ip, port))
        retry_count = 10
        transport = None
        while True:
            try:
                transport = paramiko.Transport((fuzzer_ip, port))
                transport.connect(username="nfvfuzzer", password="mima1234")
            except Exception:
                if not retry_count:
                    self.debug("[x] Cannot Connect to Image")
                    return None
                self.debug("[x] Socket Timeout, retry after 10s...")
                time.sleep(10)
                retry_count -= 1
                continue
            break
        return transport

class NDFuzzController(BaseFuzzController):
    def __init__(self, message=None, run_local=False, config=None, logger=None):
        super().__init__(message, run_local, config, logger)

        self.start_image_flag = False
        self.end_image_flag = False
        self.start_firmware_flag = False

        self.firmware_link = None
        self.fuzzer_link = None

        self._mode = "NDFuzz"
        if self.vendor == "citrix" and self.protocol == "snmp":
            self._mode = "Zsnmp"

    def start(self):
        if self.vendor not in self.config or self.protocol not in self.config[self.vendor]:
            self.error("No corresponding image file")
            return

        config = self.config[self.vendor][self.protocol]

        self.debug('[+] Getting Running Port')
        port = None
        with open(config["image_start"], "r") as start_f:
            for line in start_f.readlines():
                if "-:22 -net nic" in line:
                    port = int(re.findall(r':(\d+)-:22', line)[0])
                    break
        if not port:
            self.error("Can not get running Port")
        self.info("[!] Image running at Port {}".format(port))

        # self.debug('[+] Starting Fuzzer Image')
        # if not self.run_in_local:
        #     t_image = threading.Thread(target=self.start_image, args=(config["image_start"],))
        #     self.start_image_flag = False
        #     self.end_image_flag = False
        #     t_image.start()

        self.debug('[+] Running firmware Image')
        t_firmware = threading.Thread(target=self.start_firmware, args=(config["firmware"], port))
        t_firmware.start()

        self.debug("[+] Running NDFuzz")
        t_fuzz = threading.Thread(target=self.start_fuzzer,
                                  args=(config["fuzzer"], port, config["config"], config["input"], self.out_path))
        t_fuzz.start()

        while True:
            if self.start_fuzzer_flag:
                break

        # 执行固定时间
        exec_time = 0
        while exec_time < self.time_limit:
            time.sleep(1)
            exec_time += 1

        self.debug("[+] Time Limit!")

        self.debug("[+] Exit Firmware")
        if self.firmware_link:
            self.firmware_link.close()
        self.debug("[+] Exit Fuzzer")
        if self.fuzzer_link:
            self.fuzzer_link.close()

        self.end_image_flag = True

    def start_image(self, path):
        print(path)
        run_image = subprocess.Popen(["sudo", format(path)])
        self.start_image_flag = True
        while True:
            if self.end_image_flag:
                run_image.kill()
                break
        self.debug("[+] Exit Fuzzer Image")

    def start_firmware(self, path, port):
        # 等待镜像启动完成
        if not self.run_in_local:
            while True:
                if self.start_image_flag:
                    self.debug("[+] Waiting Image Start for 20s...")
                    time.sleep(20)
                    break

        self.firmware_link = self.start_link(self.local_ip, port)

        self.debug("[+] Communicate via SSH")
        ssh = paramiko.SSHClient()
        ssh._transport = self.firmware_link

        self.start_firmware_flag = True
        self.info("[!] Run Firmware...")
        stdin, stdout, stderr = ssh.exec_command("cd {} && sudo ./network_setup.sh && sudo ./start_qemu.sh".format(path), get_pty=True)
        # stdin, stdout, stderr = ssh.exec_command("cd {} && sudo ./start_qemu.sh".format(path), get_pty=True)
        time.sleep(1)
        stdin.write("mima1234\n")
        # self.debug("Stdout: {}".format(stdout.read().decode()))
        # self.debug("Stderr: {}".format(stderr.read().decode()))

    def start_fuzzer(self, path, port, config, seed, out):
        # 等待固件线程启动
        while True:
            if self.start_firmware_flag:
                self.debug("[+] Wait Firmware for 5s...")
                time.sleep(5)
                break

        self.fuzzer_link = self.start_link(self.local_ip, port)

        self.debug("[+] Communicate via SSH")
        ssh = paramiko.SSHClient()
        ssh._transport = self.fuzzer_link

        if self._mode == "NDFuzz":
            stdin, stdout, stderr = ssh.exec_command("cat {}/Configs/{}.config".format(path, config))

            lines = stdout.read().decode().split('\n')
            for line in lines:
                if "coverage_file =" in line:
                    self.coverage = line.split("=")[1].strip()
            self.info("[!] Coverage File : {}".format(self.coverage))

            self.info("[!] Run Fuzzer...")
            self.start_fuzzer_flag = True
            stdin, stdout, stderr = ssh.exec_command(
                "cd {} && sudo python start.py -c {} -i {} -o {} --overwrite".format(path, config, seed, out), get_pty=True)
            time.sleep(1)
            stdin.write("mima1234\n")
            # self.debug("Stdout: {}".format(stdout.read().decode()))
            # self.debug("Stderr: {}".format(stderr.read().decode()))

        elif self._mode == "Zsnmp":
            pass

class BlackBoxFuzzController(BaseFuzzController):
    def __init__(self, message=None, run_local=False, config=None, logger=None):
        super().__init__(message, run_local, config, logger)
        self.fuzzer_ip = VMEARE_FUZZER_IP

    def start(self):
        if self.vendor not in self.config or self.protocol not in self.config[self.vendor]:
            self.error("No corresponding image file")
            return

        config = self.config[self.vendor][self.protocol]

        self.debug("[+] Running Black Box Fuzz")
        t_fuzz = threading.Thread(target=self.start_fuzzer,
                                  args=(config["fuzzer"], config["target_ip"], config["input"], self.out_path))
        t_fuzz.start()

        # 等待 fuzzer 启动
        while True:
            if self.start_fuzzer_flag:
                break
            time.sleep(1)

        # 执行固定时间
        exec_time = 0
        while exec_time < self.time_limit:
            time.sleep(1)
            exec_time += 1

        self.debug("[+] Time Limit!")

        self.debug("[+] Exit Fuzzer")
        if self.fuzzer_link:
            self.fuzzer_link.close()


    def start_fuzzer(self, path, target_ip, seed, out):
        # 打开 fuzzer 连接
        self.fuzzer_link = self.start_link(self.fuzzer_ip)
        self.debug("[+] Communicate via SSH")
        ssh = paramiko.SSHClient()
        ssh._transport = self.fuzzer_link

        # 启动 fuzz
        self.info("[!] Run Fuzzer...")
        self.start_fuzzer_flag = True
        stdin, stdout, stderr = ssh.exec_command(
            "cd {} && sudo python2 zsnmp.py -t {} -c public -i {} -o {} --logAll".format(path, target_ip, seed, out), get_pty=True)
        time.sleep(1)
        stdin.write("mima1234\n")

if __name__ == '__main__':
    # m = NDFuzzMonitor(run_local=True)
    # m.start()

    msg = {
        "params":{
            "vendor": "paloalto",
            "protocol": ["snmp"],
            "time_limit": 300,
            "time_gap": 60
        },
        "source": "test"
    }
    c = NDFuzzMonitor(msg)
    c.start()
    # m.get_result_data(["00000023.case"])
