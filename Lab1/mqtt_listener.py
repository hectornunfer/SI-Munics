import paho.mqtt.client as mqtt
import tor
import mqtt as mqtt_client

MQTT_SERVER = "18.101.47.122"
MQTT_USER = "sinf"  
MQTT_PASSWORD = "HkxNtvLB3GC5GQRUWfsA"  
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60 
MQTT_TOPIC = "hnf"

def split_received_message(plaintext):
    return plaintext[:5].strip(b'\x00').decode('ascii')

def on_message(client, userdata, msg):
    plaintext = tor.decrypt_hybrid(msg.payload)
    source = split_received_message(plaintext[:5])
    message = plaintext[5:]
    if source == "END" or source == "end":
        source = split_received_message(plaintext[5:])
        message = plaintext[10:].decode('ascii')
        print("From source:" + str(source))
        print("Message:" + message)
    else:
        print("Sending message to " + str(source))
        client.publish(str(source), message)


def mqtt_client(server, port, topic, user, password, keepalive):
    client = mqtt.Client()
    client.on_message = on_message
    client.username_pw_set(user, password)
    client.connect(server, port, keepalive)
    client.subscribe(topic)
    return client

def listen():
    while True:
        client.loop_start()
        leave = input("\n Presiona una tecla para salir: \n")
        if leave != "":
            client.loop_stop()
            break
        
 # Blocking call that processes network traffic, dispatches callbacks and
 # handles reconnecting.
 # Other loop*() functions are available that give a threaded interface and a
 # manual interface.
client = mqtt_client(MQTT_SERVER, MQTT_PORT, MQTT_TOPIC, MQTT_USER, MQTT_PASSWORD , MQTT_KEEPALIVE)

listen()
