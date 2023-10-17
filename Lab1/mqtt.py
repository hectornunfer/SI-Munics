import paho.mqtt.client as mqtt
import tor

MQTT_SERVER = "18.101.47.122"
MQTT_USER = "sinf"  
MQTT_PASSWORD = "HkxNtvLB3GC5GQRUWfsA"  
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60
MQTT_TOPIC = "hnf"


def mqtt_client(server, port, topic, user, password, keepalive):
    client = mqtt.Client()
    client.username_pw_set(user, password)
    client.connect(server, port, keepalive)
    client.subscribe(topic)
    return client

def listen():
    while True:
        client.loop_start()
        leave = input("\Presiona una tecla para salir: \n")
        if leave == "":
            client.loop_stop()
            break

 # Blocking call that processes network traffic, dispatches callbacks and
 # handles reconnecting.
 # Other loop*() functions are available that give a threaded interface and a
 # manual interface.
client = mqtt_client(MQTT_SERVER, MQTT_PORT, MQTT_TOPIC, MQTT_USER, MQTT_PASSWORD , MQTT_KEEPALIVE)

cipher_message = b"Probando"
result = client.publish("hnf", tor.encrypt_nested_hybrid(["hnf","hnf","dfp"],cipher_message))
