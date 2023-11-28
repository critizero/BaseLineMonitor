import pika
import json
import time

# Create a connection to the RabbitMQ server
class TaskQueue:
    def __init__(self):
        self.control_uuid = 'aaabbbcccdddeeeba49d9ff1791bbfb0'  # 协同uuid 无需修改
        self.engine_uuid = '07b8e7db09904e68a08bd6047246ee06'  # TODO:2:使用第一步注册时获取的用户名
        credentials = pika.PlainCredentials(self.engine_uuid, 'mima1234')  # TODO:1:找协同注册消息队列获取帐号和密码
        parameters = pika.ConnectionParameters('10.26.81.92', 5672,'/', credentials)  # 连接信息，无需修改
        self.connection = pika.BlockingConnection(parameters)

    def send_task_result(self, message):
        channel = self.connection.channel()
        channel.exchange_declare(exchange='direct_exchange', exchange_type='direct')
        
        message['destination'] = self.control_uuid
        # Create a json message with the task information
        # Take TaskResult as example:

        # message = {
        #     "msg_id": "e0edf4eaf0c34e6ac5b896fd217e4b3",  #  TODO 发送消息时，调用uuid随机此消息生成唯一标识码
        #     "msg_type": 2,  # 发送结果消息时，无需修改
        #     "task_id": "d4d4a4e1e184bd9b6e2e3e0f2f6f30",  # TODO 总控发布，从接收的开始指令消息里获取
        #     "sub_task_id": "1f5f60d6f6e94e7d9c86e1e7fe84a8ff",  # TODO 总控发布，从接收的开始指令消息里获取
        #     # "source": "engine1",  # TODO 总控发布，从接收的开始指令消息里获取，注意这里填写指令消息里的destination
        #     "destination": "control",  # TODO 总控发布，从接收的开始指令消息里获取, 注意这里填写指令消息里的source
        #     "successed": True,  # TODO 若成功，bool型
        #     "error": "null",  # TODO 若失败，返回错误结果
        #     "data_uri": "2f3b9db0b3d94a3f9f8af7e6b3e75d4d",  # TODO 返回结果的标识码，需要引擎生成，如果结果数据量大则可选，否则为null
        #     "data": "a6e4e00df4e64a3e9c7d1b3f8e9c4a5b",  # TODO 返回结果json string，不能超过512M,且只支持json string
        #     "timestamp": timestamp,
        #     "signature": "null"  # 暂时为null
        # }


        # Publish the message to the exchange with the routing key
        channel.basic_publish(exchange='direct_exchange', routing_key=message['destination'], body=json.dumps(message))
        print("Sent successfully!")
        # Close the connection
        self.connection.close()

    # Define a function to send heartbeat messages, accept a time interval parameter
    def send_heartbeat(self, interval=60): # set the default time interval to 60 seconds
        # Create a connection parameter object, set the address, port, username and password of rabbitmq
        credentials = pika.PlainCredentials(self.rabbitmq_username, self.rabbitmq_password)

        # Create a connection object, which is used to connect to the rabbitmq server
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(self.rabbitmq_server_address, self.rabbitmq_server_port, '/', credentials))

        # Create a channel object, which is used to send and receive messages
        channel = connection.channel()

        # Declare an exchange, type is direct, which is used to route messages to queues
        channel.exchange_declare(exchange="heartbeat_exchange", exchange_type="direct")

        # Get the current timestamp
        timestamp = int(time.time())
        # Construct a heartbeat message, containing the timestamp
        message = {
                  "msg_id": "a0b1c2d3-e4f5-6789-10ab-cdef11121314",
                  "msg_type": 3,
                  "engine_id": "a0b1c2d3-e4f5-6789-10ab-cdef11121314",
                  "source": "engine1",
                  "destination": "control",
                  "timestamp": timestamp,
                  "signature": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6y+Z8fHJlZj3nS1Q9PfMtj4zLjZt9uRzqZkVwYXJ0aW5nLmNvbS9hcGkvdjEvbWVzc2FnZ"
                }
        # Send the message to the exchange, specify the routing key as "heartbeat"
        channel.basic_publish(exchange="heartbeat_exchange", routing_key="control", body=message)
        # Print the message content
        print(f"Sent {message}")
        # Wait for the specified time interval
        time.sleep(interval)
        # Recursively call itself, to achieve loop sending
        self.send_heartbeat(interval)

        
          

# ProcesUpdate message example
# {
#   "msg_id": "f3c4a8b6-7f4d-4a6e-9d6e-7f8f4d5c9b7a",
#   "msg_type": 1,
#   "task_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
#   "sub_task_id": "6d5c4b3a-2f1e-0d9c-8b7a-f6e5d4c3b2a1",
#   "source": "engine1",
#   "destination": "control",
#   "percent": 0.75,
#   "current_value": 150.0,
#   "total_value": 200.0,
#   "timestamp": "20231113092152",
#   "signature":"c7f5a0e9e3d245b6891a2c4d9b6c1f5e"
# }

# Heartbeat message example
# {
#   "msg_id": "a0b1c2d3-e4f5-6789-10ab-cdef11121314",
#   "msg_type": 3,
#   "engine_id": "a0b1c2d3-e4f5-6789-10ab-cdef11121314",
#   "source": "engine1",
#   "destination": "control",
#   "timestamp": "20231113094936",
#   "signature": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6y+Z8fHJlZj3nS1Q9PfMtj4zLjZt9uRzqZkVwYXJ0aW5nLmNvbS9hcGkvdjEvbWVzc2FnZ"
# }
