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


def create_dir(dir):
    if not os.path.exists(dir):
        os.makedirs(dir)


neko = threading.Lock()


class NDFuzzMonitor:
    def __init__(self, message=None, debug=False):
        self.message = message
        self.protocols = message["params"]["protocol"]
        self.local_ip = '10.26.81.7'
        self.thread_info = {}

        self.logger = logging.getLogger('BaseLineMonitor')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(formatter)
        self.logger.addHandler(console)
        self.logger.setLevel(logging.DEBUG)

        with open('config.json', 'r') as conf_f:
            self.config = json.load(conf_f)

        self.is_debug = debug

    def start(self):
        os.system("rm -f result/*")
        for protocol in self.protocols:
            self.info("======Deliver Task : {}======".format(protocol))
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

    def run(self, msg):
        config = self.config[msg["vendor"]][msg["protocol"]]
        out_path = "{}/out_{}_{}_BY_BLM".format(config["fuzzer"], msg["vendor"], msg["protocol"])

        res_pre = "log/{}_{}_pre.txt".format(msg["vendor"], msg["protocol"])
        with open(res_pre, "a+") as res_pre_f:
            res_pre_f.truncate(0)

        port = None
        with open(config["image_start"], "r") as start_f:
            for line in start_f.readlines():
                if "-:22 -net nic" in line:
                    port = int(re.findall(r':(\d+)-:22', line)[0])
                    break

        info = {
            "path": out_path,
            "port": port,
            "file": res_pre
        }

        neko.acquire()
        self.thread_info[msg["protocol"]] = info
        neko.release()

        runner = NDFuzzController(message=msg, config=self.config, logger=self.logger)
        runner.start()

    def get_link(self, port):
        retry_count = 5
        transport = None
        while True:
            try:
                transport = paramiko.Transport((self.local_ip, port))
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
        self.info("=======SCANNING RESULT======")
        for protocol in self.protocols:
            t_scanner = threading.Thread(target=self.get_result, args=(self.thread_info[protocol], protocol))
            t_scanner.start()

    def get_result(self, info, protocol):

        scan_link = self.get_link(info["port"])
        ssh = paramiko.SSHClient()
        ssh._transport = scan_link

        stdin, stdout, stderr = ssh.exec_command("ls {}/crashes".format(info["path"]))
        res = stdout.read().decode().strip()

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
                sftp.get("{}/crashes/{}".format(info["path"], name), "result/{}_{}".format(protocol, name))
                pre_res.write(name + "\n")

        # stdin, stdout, stderr = ssh.exec_command("tail -n 2 {} | head -n 1".format(self.coverage))
        # coverage = stdout.read().decode().strip()

        if not self.is_debug and new_list:
            producer_message = self.generate_producer_message(new_list, protocol)

            self.logger.info("[{}] Return Message : {}".format(protocol, producer_message))

            producer = TaskQueue()
            producer.send_task_result(producer_message)

    def generate_producer_message(self, new_list, protocol):
        successed, error, data = self.get_result_data(new_list, protocol)

        message = self.message

        message["msg_id"] = str(uuid.uuid4())
        message["msg_type"] = 2
        message["destination"] = message["source"]
        message["successed"] = successed
        message["error"] = error
        message["data_uri"] = "null"
        message["data"] = data
        message["timestamp"] = int(time.time())
        message["signature"] = "null"

        return message

    @staticmethod
    def get_result_data(new_list, protocol):
        result_dict = {
            "header": ["protocol", "message type", "payload"]
        }
        for case_name in new_list:
            with open("result/{}_{}".format(protocol, case_name), "r") as case_f:
                content = case_f.readline()
                payload_msg_type = ast.literal_eval(content)[0]
                payload = ast.literal_eval(content)[-1]
                result_dict[protocol + '_' + case_name] = {"protocol": protocol,
                                                           "message": payload_msg_type,
                                                           "payload": payload}

        successed = True
        error = "null"
        data = json.dumps(result_dict)
        return successed, error, data


class NDFuzzController:
    def __init__(self, message=None, run_local=False, config=None, logger=None):
        self.local_ip = '10.26.81.7'

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

        self.pre_result_idx = None
        self.res_pre = None
        # self.res_new = None
        self.coverage = None

        self.start_image_flag = False
        self.end_image_flag = False
        self.start_firmware_flag = False
        self.start_fuzzer_flag = False

        self.firmware_link = None
        self.fuzzer_link = None

        self.message = message

        create_dir("log")
        create_dir("result")

    def error(self, error_msg):
        self.logger.error("\033[91m<{}> | {}\033[0m".format(self.protocol, error_msg))
        exit(0)

    def debug(self, debug_msg):
        self.logger.debug("\033[93m<{}> | {}\033[0m".format(self.protocol, debug_msg))

    def info(self, info_msg):
        self.logger.info("\033[92m<{}> | {}\033[0m".format(self.protocol, info_msg))

    def start(self):
        if self.vendor not in self.config or self.protocol not in self.config[self.vendor]:
            self.error("No corresponding image file")
            return

        config = self.config[self.vendor][self.protocol]
        out_path = "{}/out_{}_{}_BY_BLM".format(config["fuzzer"], self.vendor, self.protocol)
        # out_path = "{}/out_srx_zsnmp_fb_1116/".format(config["fuzzer"])
        self.info("[!] Output file path : {}".format(out_path))

        # 本地结果
        self.res_pre = "log/{}_{}_pre.txt".format(self.vendor, self.protocol)
        # self.res_new = "log/{}_{}_new.txt".format(vendor, protocol)
        with open(self.res_pre, "a+") as res_pre:
            res_pre.truncate(0)
        # with open(self.res_new, "a+") as res_new:
        #     res_new.truncate(0)
        os.system("rm -f result/*")

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

        self.debug('[+] Starting Fuzzer Image')
        if not self.run_in_local:
            t_image = threading.Thread(target=self.start_image, args=(config["image_start"],))
            self.start_image_flag = False
            self.end_image_flag = False
            t_image.start()

        self.debug('[+] Running firmware Image')
        t_firmware = threading.Thread(target=self.start_firmware, args=(config["firmware"], port))
        t_firmware.start()

        self.debug("[+] Running NDFuzz")
        t_fuzz = threading.Thread(target=self.start_fuzzer,
                                  args=(config["fuzzer"], port, config["config"], config["input"], out_path))
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
        run_image = subprocess.Popen(["sudo", format(path)])
        self.start_image_flag = True
        while True:
            if self.end_image_flag:
                run_image.kill()
                break
        self.debug("[+] Exit Fuzzer Image")

    def start_link(self, port):
        self.debug("[+] Link via SSH...")
        retry_count = 10
        transport = None
        while True:
            try:
                transport = paramiko.Transport((self.local_ip, port))
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

    def start_firmware(self, path, port):
        # 等待镜像启动完成
        if not self.run_in_local:
            while True:
                if self.start_image_flag:
                    self.debug("[+] Waiting Image Start for 20s...")
                    time.sleep(20)
                    break

        self.firmware_link = self.start_link(port)

        self.debug("[+] Communicate via SSH")
        ssh = paramiko.SSHClient()
        ssh._transport = self.firmware_link

        # stdin, stdout, stderr = ssh.exec_command("cd {} &&ls".format(path), get_pty=True)
        # time.sleep(1)
        # stdin.write("mima1234\n")
        # print(stdout.read().decode())

        # self.logger.info("[!] Set Firmware network...")
        # stdin, stdout, stderr = ssh.exec_command("cd {} && sudo ./network_setup.sh".format(path), get_pty=True)
        # time.sleep(1)
        # stdin.write("mima1234\n")
        # print(stdout.read().decode())

        self.start_firmware_flag = True
        self.info("[!] Run Firmware...")
        # stdin, stdout, stderr = ssh.exec_command("cd {} && sudo ./network_setup.sh && sudo ./start_qemu.sh".format(path), get_pty=True)
        stdin, stdout, stderr = ssh.exec_command("cd {} && sudo ./start_qemu.sh".format(path),
                                                 get_pty=True)
        time.sleep(1)
        stdin.write("mima1234\n")

    def start_fuzzer(self, path, port, config, seed, out):
        # 等待固件线程启动
        while True:
            if self.start_firmware_flag:
                self.debug("[+] Wait Firmware for 5s...")
                time.sleep(5)
                break

        self.fuzzer_link = self.start_link(port)

        self.debug("[+] Communicate via SSH")
        ssh = paramiko.SSHClient()
        ssh._transport = self.fuzzer_link

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


if __name__ == '__main__':
    # m = NDFuzzMonitor(run_local=True)
    # m.start()

    msg = {
        "params":{
            "vendor": "asa",
            "protocol": ["dhcp", "snmp"],
            "time_limit": 300,
            "time_gap": 60
        },
        "source": "test"
    }
    c = NDFuzzMonitor(msg)
    c.start()
    # m.get_result_data(["00000023.case"])
