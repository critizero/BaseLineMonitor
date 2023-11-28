import pika
import json
from main import NDFuzzMonitor

# MESSAGE_FILE_NAME = "/appdata/message"

class Consumer:
    def __init__(self):
        self.engine_uuid = '07b8e7db09904e68a08bd6047246ee06'  # TODO:1:找协同注册消息队列获取uuid和密码
        credentials = pika.PlainCredentials(self.engine_uuid, 'mima1234')  #
        parameters = pika.ConnectionParameters('10.26.81.92', 5672, '/', credentials)
        self.connection = pika.BlockingConnection(parameters)

    def receive_task(self):
        channel = self.connection.channel()
        channel.exchange_declare(exchange='direct_exchange', exchange_type='direct')
        result = channel.queue_declare(queue=self.engine_uuid)
        queue_name = result.method.queue
        channel.queue_bind(exchange='direct_exchange', queue=queue_name, routing_key=self.engine_uuid)

        # Define a callback function to process the message
        def callback(ch, method, properties, body):
            # Convert the message to a json object
            self.message = json.loads(body)

            # # 将 message 信息保存到本地
            # with open(MESSAGE_FILE_NAME, "w") as f:
            #     print("Write message info to %s" % MESSAGE_FILE_NAME)
            #     json.dump(self.message, f)


            # Print the message
            print("Received %r" % self.message)
            # Do something with the message
            self.process_message()

        # Consume the message from the queue
        channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)

        # Start the consumer loop
        print('Waiting for messages. To exit press CTRL+C')
        channel.start_consuming()

    # Process the received messages
    def process_message(self):
        if self.message['msg_type'] == 0:

            self.message["params"] = {
                "vendor": "asa",
                "protocol": ["dhcp", "snmp"],
                "time_limit": 3000,
                "time_gap": 60
            }
            ndfuzz_monitor = NDFuzzMonitor(self.message)

            ndfuzz_monitor.start()
            # TOOD: 返回调用是否成功的信息
            
            # pass
            # TODO 消息处理，根据各自引擎进处理
        
        elif self.message['msg_type'] == 4:
            pass
        elif self.message['msg_type'] == 5:
            pass

if __name__ == '__main__':
    c = Consumer()
    c.receive_task()
