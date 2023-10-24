import paho.mqtt.client as mqtt
import functions
import random
import ast

MQTT_SERVER = "18.101.47.122"
MQTT_USER = "sinf"  
MQTT_PASSWORD = "ASK"  
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60 
MQTT_TOPIC = "hnf-alice"
# This param is mandatory to know q, the length of the c
# Every message is sended with 10 caracters, this are 80 bits
MAX_LENGTH = 10
# R vector sended by Bob
R_bob = []
# Alice answer
B_alice = 'vietnam'
# This boolean is used to probe what happens if Alice changes
# her seed when she sends it. Bob should detect that g0 differs.
CHANGE_SEED = False
# This boolean is used to probe what happens if Alice changes
# her answer when she sends it. Bob should detect that this 
# message doesn't match with the commitment.
CHANGE_ANSWER = True
# When a message is received
def on_message(client, userdata, msg):
    msg_payload_str = msg.payload.decode('utf-8')
    m_splitted = msg_payload_str.split(":")
    message = m_splitted[1]
    # If the message starts with r, means that Bob is sending the random vector r
    if m_splitted[0] == 'r':
        # Commit stage
        # This order converts a string into a binary list
        R_bob = ast.literal_eval(message)
        # Format the message adjusting it to the max_length
        bin_alice_b = functions.format_message(B_alice, MAX_LENGTH * 8)
        # Generate a seed of length n = 3 * m (m = message_length)
        seed = [random.randint(0, 1) for _ in range(len(3 * bin_alice_b))]
        # Compute the commitment e
        alice_e, alice_gr, alice_g0 = functions.compute_e(bin_alice_b, str(seed), R_bob)
        print(f"Sending e to Bob\n")
        client.publish("hnf-bob", f"e:{alice_e}")
        print(f"Sending G0 to Bob\n")
        client.publish("hnf-bob", f"g0:{alice_g0}")
        # Proof and verify stage
        print(f"Sending s to Bob\n")
        # Alice changes the seed, so she creates a new one
        seed_modified = [random.randint(0, 1) for _ in range(len(3 * bin_alice_b))]
        # Depending if you want to make Alice send the correct seed or change it
        if CHANGE_SEED:
            client.publish("hnf-bob", f"s:{str(seed_modified)}")
        else:
            client.publish("hnf-bob", f"s:{str(seed)}")
        # Alice changes the answer, so she creates a new one
        bin_alice_b_modified = functions.format_message('beach', MAX_LENGTH * 8)
        print(f"Sending (b1...bm) to Bob\n")
        # Depending if you want to make Alice send the correct answer or change it
        if CHANGE_ANSWER:
            client.publish("hnf-bob", f"b:{bin_alice_b_modified}")
        else:
            client.publish("hnf-bob", f"b:{bin_alice_b}")
    # If the message starts with end, means that Bob verified (succesfully or not) the answer given
    elif m_splitted[0] == 'end':
        print(message) 

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
