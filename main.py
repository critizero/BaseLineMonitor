import os
import re
import json
import logging
import socket

import paramiko
import threading
import subprocess
import time

import uuid
from producer import *

class NDFuzzMonitor:
    def __init__(self, message = None, run_local = False):
        with open('config.json', 'r') as conf_f:
            self.config = json.load(conf_f)

        self.local_ip = '10.26.81.7'

        self.logger = logging.getLogger('BaseLineMonitor')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(formatter)
        self.logger.addHandler(console)
        self.logger.setLevel(logging.DEBUG)

        self.run_in_local = run_local

        self.result_turn = 0

        if message:
            self.vendor = message["paras"]["vendor"]
            self.protcol = message["paras"]["protocol"]
            self.time_limit = message["paras"]["time_limit"]
            self.time_gap = message["paras"]["time_gap"]
        else:
            # for local test
            self.vendor = "srx"
            self.protcol = "snmp"
            self.time_limit = 300
            self.time_gap = 0

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

    def error(self, error_msg):
        self.logger.error(error_msg)
        exit(0)

    def start(self):

        if self.vendor not in self.config or self.protocol not in self.config[self.vendor]:
            self.error("No corresponding image file")
            return

        config = self.config[self.vendor][self.protocol]
        out_path = "{}/out_{}_{}_BY_BLM".format(config["fuzzer"], self.vendor, self.protocol)
        # out_path = "{}/out_srx_zsnmp_fb_1116/".format(config["fuzzer"])
        self.logger.info("[!] Output file path : {}".format(out_path))

        # 本地结果
        self.res_pre = "log/{}_{}_pre.txt".format(self.vendor, self.protocol)
        # self.res_new = "log/{}_{}_new.txt".format(vendor, protocol)
        with open(self.res_pre, "a+") as res_pre:
            res_pre.truncate(0)
        # with open(self.res_new, "a+") as res_new:
        #     res_new.truncate(0)
        os.system("rm -f result/*")

        self.logger.debug('[+] Getting Running Port')
        port = None
        with open(config["image_start"], "r") as start_f:
            for line in start_f.readlines():
                if self.local_ip in line:
                    port = int(re.findall(r'{}:(\d+)'.format(self.local_ip), line)[0])
                    break
        if not port:
            self.error("Can not get running Port")
        self.logger.info("[!] Image running at Port {}".format(port))

        self.logger.debug('[+] Starting Fuzzer Image')
        if not self.run_in_local:
            t_image = threading.Thread(target=self.start_image, args=(config["image_start"],))
            self.start_image_flag = False
            self.end_image_flag = False
            t_image.start()

        self.logger.debug('[+] Running firmware Image')
        t_firmware = threading.Thread(target=self.start_firmware, args=(config["firmware"], port))
        t_firmware.start()

        self.logger.debug("[+] Running NDFuzz")
        t_fuzz = threading.Thread(target=self.start_fuzzer, args=(config["fuzzer"], port, config["config"], config["input"], out_path))
        t_fuzz.start()

        while True:
            if self.start_fuzzer_flag:
                break

        # 执行固定时间
        exec_time = 0
        while exec_time < self.time_limit:
            time.sleep(1)
            exec_time += 1

            if exec_time % self.time_gap == 0:
                t_scan = threading.Thread(target=self.scan_result, args=(port, out_path))
                t_scan.start()

        # 最后检查一次结果
        t_scan = threading.Thread(target=self.scan_result, args=(port, out_path))
        t_scan.start()

        self.logger.debug("[+] Time Limit!")

        self.logger.debug("[+] Exit Firmware")
        if self.firmware_link:
            self.firmware_link.close()
        self.logger.debug("[+] Exit Fuzzer")
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
        self.logger.debug("[+] Exit Fuzzer Image")

    def start_link(self, port):
        self.logger.debug("[+] Link via SSH...")
        retry_count = 10
        transport = None
        while True:
            try:
                transport = paramiko.Transport((self.local_ip, port))
                transport.connect(username="nfvfuzzer", password="mima1234")
            except Exception:
                if not retry_count:
                    self.logger.debug("[x] Cannot Connect to Image")
                    return None
                self.logger.debug("[x] Socket Timeout, retry after 10s...")
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
                    self.logger.debug("[+] Waiting Image Start for 20s...")
                    time.sleep(20)
                    break

        self.firmware_link = self.start_link(port)

        self.logger.debug("[+] Communicate via SSH")
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
        self.logger.info("[!] Run Firmware...")
        stdin, stdout, stderr = ssh.exec_command("cd {} && sudo ./network_setup.sh && sudo ./start_qemu.sh".format(path), get_pty=True)
        # stdin, stdout, stderr = ssh.exec_command("cd {} && sudo ./start_qemu.sh".format(path),
        #                                          get_pty=True)
        time.sleep(1)
        stdin.write("mima1234\n")

    def start_fuzzer(self, path, port, config, seed, out):
        # 等待固件线程启动
        while True:
            if self.start_firmware_flag:
                self.logger.debug("[+] Wait Firmware for 5s...")
                time.sleep(5)
                break

        self.fuzzer_link = self.start_link(port)

        self.logger.debug("[+] Communicate via SSH")
        ssh = paramiko.SSHClient()
        ssh._transport = self.fuzzer_link

        stdin, stdout, stderr = ssh.exec_command("cat {}/Configs/{}.config".format(path, config))

        lines = stdout.read().decode().split('\n')
        for line in lines:
            if "coverage_file =" in line:
                self.coverage = line.split("=")[1].strip()
        self.logger.info("[!] Coverage File : {}".format(self.coverage))

        self.logger.info("[!] Run Fuzzer...")
        self.start_fuzzer_flag = True
        stdin, stdout, stderr = ssh.exec_command("cd {} && sudo python start.py -c {} -i {} -o {} --overwrite".format(path, config, seed, out), get_pty=True)
        time.sleep(1)
        stdin.write("mima1234\n")

    def scan_result(self, port, out):
        self.logger.debug("[+] Result Scan {}".format(self.result_turn))
        self.result_turn += 1

        # # Test
        # self.coverage = "/home/zoe/Desktop/bb_coverage/vsrx_19.4/snmp_0319/vsrx_coverage"

        scan_link = self.start_link(port)
        ssh = paramiko.SSHClient()
        ssh._transport = scan_link

        self.logger.debug("[+] Reading Result...")
        stdin, stdout, stderr = ssh.exec_command("ls {}/crashes".format(out))
        res = stdout.read().decode().strip()

        pre = []
        res_list = res.split('\n')
        with open(self.res_pre, "r") as pre_res:
            for line in pre_res.readlines():
                pre.append(line.strip())

        new_list = []
        for file in res_list:
            if file == '':
                continue
            if file not in pre:
                new_list.append(file)
        self.logger.debug("[!] New Result : {}".format(new_list))

        sftp = paramiko.SFTPClient.from_transport(scan_link)

        with open(self.res_pre, "a") as pre_res:
            for name in new_list:
                sftp.get("{}/crashes/{}".format(out, name), "result/{}".format(name))
                pre_res.write(name + "\n")
        
        # with open(self.res_new, "w") as res_new:
        #     res_new.write(" ".join(new_list))

        stdin, stdout, stderr = ssh.exec_command("tail -n 2 {} | head -n 1".format(self.coverage))
        coverage = stdout.read().decode().strip()
        self.logger.info("[!] Coverage : {}".format(coverage))

        producer_message = self.generate_producer_message(new_list)
        self.logger.debug("[+] Return Message : {}".format(json.dumps(producer_message)))

        if not self.run_in_local:
            producer = TaskQueue()
            producer.send_task_result(producer_message)

    def generate_producer_message(self, new_list):
        successed, error, data = self.get_result_data(new_list)

        message = self.message
        message["msg_id"] = str(uuid.uuid4())
        message["msg_type"] = 2
        message["destination"] = self.message["source"]
        message["successed"] = successed
        message["error"] = error
        message["data_uri"] = "null"
        message["data"] = data
        message["timestamp"] = int(time.time())
        message["signature"] = "null"

        return message

    def get_result_data(self, new_list):
        result_list = []
        for case_name in new_list:
            with open(case_name, "r") as case_f:
                content = case_f.readlines()
                result_list.append(' '.join(content).strip())
        successed = True
        error = "null"
        data = "\n".join(result_list)
        return successed, error, data
        

if __name__ == '__main__':
    m = NDFuzzMonitor(run_local=True)
    m.start()