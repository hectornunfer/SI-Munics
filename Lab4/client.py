import paho.mqtt.client as mqtt
import functions
import ast
import functions
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization




MQTT_SERVER = "18.101.47.122"
MQTT_USER = "sinf"  
MQTT_PASSWORD = "X"
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60
MQTT_TOPIC = "hnf.in"
other_pkey = None
root_key = b'00112233445566778899aabbccddeeff'

def on_message(client, userdata, msg):
    global other_pkey
    msg_payload_str = msg.payload.decode('utf-8')
    m_splitted = msg_payload_str.split(":")
    if m_splitted[0] == 'start':
        other_pkey = x25519.X25519PublicKey.from_public_bytes(ast.literal_eval(m_splitted[1]))
        print(f"Public key received:\t{ast.literal_eval(m_splitted[1])}")
    else :
        received_public_key = x25519.X25519PublicKey.from_public_bytes(ast.literal_eval(m_splitted[0]))
        print(f"Public key received:\t{ast.literal_eval(m_splitted[0])}")
        other_pkey = received_public_key
        iv = m_splitted[1]
        cipher = m_splitted[2]
        print(f"Ciphertext received:\t{cipher}")
        derived = functions.ratchet_dh(private_key,received_public_key)
        key = functions.ratchet_symmetric(derived,root_key)
        message = functions.decrypt(key, ast.literal_eval(iv), ast.literal_eval(cipher))
        print("Message received:\t" + message.decode('utf-8'))


# Configuration of the client
def mqtt_client(server, port, topic, user, password, keepalive):
    client = mqtt.Client()
    client.on_message = on_message
    client.username_pw_set(user, password)
    client.connect(server, port, keepalive)
    client.subscribe(topic)
    return client

def listen():
    n = 1
    while True:
        global private_key
        global public_key
        client.loop_start()
        message = input("\nEnter message: \n")
        if n > 2:
            private_key, public_key = functions.generate_dh_key_pair()
            n = 1
        derived = functions.ratchet_dh(private_key,other_pkey)
        key = functions.ratchet_symmetric(derived,root_key)
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(message.encode('utf-8')) + padder.finalize()
        iv, ciphertext = functions.encrypt(key,padded_plaintext)
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        client.publish("hnf.out", str(public_bytes) + ':' + str(iv) + ':' + str(ciphertext))
        n += 1

        
# Create the MQTT client
private_key, public_key = functions.generate_dh_key_pair()
client = mqtt_client(MQTT_SERVER, MQTT_PORT, MQTT_TOPIC, MQTT_USER, MQTT_PASSWORD, MQTT_KEEPALIVE)
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
msg = 'start:' + str(public_bytes)
client.publish("hnf.out", msg)
# Keeps listening
listen()