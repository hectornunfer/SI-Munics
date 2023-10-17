import paho.mqtt.client as mqtt
import tor
import mqtt as mqtt_client

MQTT_SERVER = "18.101.47.122"
MQTT_USER = "sinf"  
MQTT_PASSWORD = "HkxNtvLB3GC5GQRUWfsA"  
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60 
MQTT_TOPIC = "hnf"

# It gets the first 5 bytes of a plaintext and ignores the 0 byte \x00 
def split_received_message(plaintext):
    return plaintext[:5].strip(b'\x00').decode('ascii')

# When a message is received
def on_message(client, userdata, msg):
    # It decrypts using hybrid decryption
    plaintext = tor.decrypt_hybrid(msg.payload)
    # Check if the first 5 bytes are equal to "end"
    source = split_received_message(plaintext[:5])
    # The encrypted message to be sent if i'm not the destination
    message = plaintext[5:]
    if source == "END" or source == "end":
        # Same as above, if we are the destination, we get the source, that will be in the next 5 bytes
        source = split_received_message(plaintext[5:])
        # Getting the original message
        message = plaintext[10:].decode('ascii')
        print("From source: " + str(source))
        print("Message: " + message)
    else:
        # If I'm not the destination, i send it to the next hope
        print("Sending message to: " + str(source))
        client.publish(str(source), message)

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
        leave = input("\nPresiona una tecla para salir: \n")
        if leave != "":
            client.loop_stop()
            break
        
# Create the MQTT client
client = mqtt_client(MQTT_SERVER, MQTT_PORT, MQTT_TOPIC, MQTT_USER, MQTT_PASSWORD , MQTT_KEEPALIVE)

# Keeps listening
listen()
