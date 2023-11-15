from datetime import datetime

import pika
import json
import uuid


class Producer:
    def __init__(self):
        self.credentials = pika.PlainCredentials('vkg_test', 'mima1234')

    def send_task(self, **kwargs):
        parameters = pika.ConnectionParameters('10.26.81.18', 5672, kwargs['vhost'], self.credentials)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        channel.exchange_declare(exchange='direct_exchange', exchange_type='direct')
        message = {
            "msg_id": str(uuid.uuid4()),
            "msg_type": 0,
            "task_id": 'ba6d70eadbcd43c3aa799ae0a5e8229d',  # 任务基线任务ID
            "sub_task_id": 'e03474d13e9d47908ea86b120bc7a056',  # 子任务ID
            "source": 'aaabbbcccdddeeeba49d9ff1791bbfb0',  # 协同uuid
            "destination": kwargs['vhost'],  # 工具uuid
            "action": 0,  # 0:创建并执行任务; 1:创建并挂起任务; 2:挂起已创建的任务; 3:恢复被挂起的任务; 4:取消任务; 5:重新执行;
            "params": {  # 引擎自行跑任务需要的配置

            },
            "data_uri": None,
            "data": {
                'target_file': {'file_name': 'httpd',
                                'storage_uri': '2d40f37630b5a46c27254c06dee90580'}
            },
            "timestamp": datetime.now().strftime('%Y%m%d%H%M%S%f')[:-3],
            "signature": '暂时空'
        }
        print(message['destination'])
        channel.basic_publish(exchange='direct_exchange', routing_key=message['destination'], body=json.dumps(message))
        print("Sent successfully!")
        connection.close()


if __name__ == '__main__':
    a = Producer()
    destination = '59c90dc5d86342f293d824cded01bfa0' # 设置自己的 uuid
    a.send_task(**dict(vhost=destination))