import paho.mqtt.client as mqtt

MQTT_SERVER = "18.101.47.122"
MQTT_USER = "sinf"  
MQTT_PASSWORD = "ASK"  
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60
MQTT_TOPIC = "hnf/alice"
MAX_LENGTH = 10

def mqtt_client(server, port, topic, user, password, keepalive):
    client = mqtt.Client()
    client.username_pw_set(user, password)
    client.connect(server, port, keepalive)
    client.subscribe(topic)
    return client

client = mqtt_client(MQTT_SERVER, MQTT_PORT, MQTT_TOPIC, MQTT_USER, MQTT_PASSWORD , MQTT_KEEPALIVE)
# Start the vector bit commitment protocol.
client.publish("hnf-bob", f"start: Hello Bob, I have my answer, let's commit it. Send me r.")