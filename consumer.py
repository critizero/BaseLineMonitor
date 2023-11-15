import pika
import json
from main import NDFuzzMonitor

# MESSAGE_FILE_NAME = "/appdata/message"

class TaskQueue:
    def __init__(self):
        self.rabbitmq_server_address = '192.168.31.252'
        self.rabbitmq_server_port = 5672
        self.message = None

        # RabbitMQ user and password
        # TODO Please contact the collaborative platform developer and rabbitmq server administrator to add permissions
        self.rabbitmq_username = 'your_username'
        self.rabbitmq_password = 'your_password'

    def receive_task(self):
        # Create a connection to the RabbitMQ server
        credentials = pika.PlainCredentials(self.rabbitmq_username, self.rabbitmq_password)
        connection = pika.BlockingConnection(pika.ConnectionParameters(self.rabbitmq_server_address, self.rabbitmq_server_port, '/', credentials))
        channel = connection.channel()

        # Declare a direct exchange
        channel.exchange_declare(exchange='direct_exchange', exchange_type='direct')

        # Declare a queue
        result = channel.queue_declare(queue='', exclusive=True)
        queue_name = result.method.queue

        # Bind the queue to the exchange with the routing key
        channel.queue_bind(exchange='direct_exchange', queue=queue_name, routing_key='engine1')

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
            ndfuzz_monitor = NDFuzzMonitor(self.message)

            ndfuzz_monitor.start()
            # TOOD: 返回调用是否成功的信息
            
            # pass
            # TODO 消息处理，根据各自引擎进处理
        
        elif self.message['msg_type'] == 4:
            pass
        elif self.message['msg_type'] == 5:
            pass