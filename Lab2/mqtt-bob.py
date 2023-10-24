import paho.mqtt.client as mqtt
import functions
import ast

MQTT_SERVER = "18.101.47.122"
MQTT_USER = "sinf"  
MQTT_PASSWORD = "ASK"  
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60
MQTT_TOPIC = "hnf-bob"
# This param is mandatory to know q, the length of the c
# Every message is sended with 10 caracters, this are 80 bits
MAX_LENGTH = 10
# R vector that Bob will send to Alice
r_bob = []
# The q param is 3 * max_length * 8, because each element of the message is represented with 8 bits
q = 3 * MAX_LENGTH * 8 # MAX_LENGTH is the number of elements of the string, in binary, each symbol are 8 bits
# Generates random vector r
r = functions.random_vector_r(q)
# Received params from Alice
alice_e = []
alice_g0 = []
alice_s = [] 
alice_b = []
def on_message(client, userdata, msg):
    global alice_e
    global alice_g0
    global alice_s
    global alice_b
    msg_payload_str = msg.payload.decode('utf-8')
    m_splitted = msg_payload_str.split(":")
    message = m_splitted[1]
    # First message to start the commitment protocol
    if m_splitted[0] == 'start':
        print(f"Alice said: {message}\n")
        client.publish("hnf-alice", f"r:{str(r)}")
    # Receives Alice e
    elif m_splitted[0] == 'e':
        print(f"Received e from Alice\n")
        alice_e = ast.literal_eval(message)
    # Receives Alice g0
    elif m_splitted[0] == 'g0':
        print(f"Received g0 from Alice\n")
        alice_g0 = ast.literal_eval(message)
    # Receives Alice s
    elif m_splitted[0] == 's':
        print(f"Received s from Alice\n")
        alice_s = ast.literal_eval(message)
    # Receives Alice b(message)
    elif m_splitted[0] == 'b':
        print(f"Received b from Alice\n")
        # Converts string to binary list
        alice_b = ast.literal_eval(message) 
        # Checks if the seed and the message given can be verified with the commitment e  
        verify_s,verify_m = functions.check_e(alice_b, alice_s, r, alice_e,alice_g0)
        # If the seed was verified succesfully:
        if verify_s == True:
            # If the message was verified succesfully:
            if verify_m == True:
                print("Alice sent the commited answer.\n")
                client.publish("hnf-alice", f"end:✓✓✓✓ Hello Alice, I've verified succesfully your answer.\n")
            # If not:
            else:
                print("Alice modified the answer.\n")
                client.publish("hnf-alice", f"end:XXXX Hello Alice, I know that you changed your answer, don't lie!!!\n")
        # If not:
        else:
            print("Alice modified the seed s.\n")
            client.publish("hnf-alice", f"end:XXXX Hello Alice, you sended me a wong seed s.\n")

# Configuration of the client
def mqtt_client(server, port, topic, user, password, keepalive):
    client = mqtt.Client()
    client.on_message = on_message
    client.username_pw_set(user, password)
    client.connect(server, port, keepalive)
    client.subscribe(topic)
    return client
# It keeps listening while it receives any key from terminal
def listen():
    while True:
        client.loop_start()
        leave = input("\nPress a key to skip: \n")
        if leave != "":
            client.loop_stop()
            break
        
# Create the MQTT client
client = mqtt_client(MQTT_SERVER, MQTT_PORT, MQTT_TOPIC, MQTT_USER, MQTT_PASSWORD , MQTT_KEEPALIVE)

# Keeps listening
listen()
