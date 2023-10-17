import paho.mqtt.client as mqtt
import tor

MQTT_SERVER = "18.101.47.122"
MQTT_USER = "sinf"  
MQTT_PASSWORD = "HkxNtvLB3GC5GQRUWfsA"  
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60
MQTT_TOPIC = "hnf"

# Configuration of the client
def mqtt_client(server, port, topic, user, password, keepalive):
    client = mqtt.Client()
    client.username_pw_set(user, password)
    client.connect(server, port, keepalive)
    client.subscribe(topic)
    return client

# Create the MQTT client
client = mqtt_client(MQTT_SERVER, MQTT_PORT, MQTT_TOPIC, MQTT_USER, MQTT_PASSWORD , MQTT_KEEPALIVE)

cipher_message = b"Probando"
# The path to send the message, the first relay have to be me always, it can't not be ommited due the implementation
path = ["hnf", "hnf"]
# Implements the nested encryption with a path given
encrypted_to_send = tor.encrypt_nested_hybrid(path,cipher_message)
# Publishing a message on the topic of the FIRST RELAY, not the last one.
result = client.publish("hnf", encrypted_to_send)
