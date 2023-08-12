import time as t
import json
import AWSIoTPythonSDK.MQTTLib as AWSIoTpyMQTT


# Client configuration with endpoint and credentials
myClient = AWSIoTpyMQTT.AWSIoTMQTTClient("testDevice")
myClient.configureEndpoint('aiy0i9khf86c-ats.iot.us-east-1.amazonaws.com',8883)
myClient.configureCredentials("AmazonRootCA1.pem","19c6c26982d07c36748cc182b65a711fb5e269aa88e8a29602afc93a12268b5a-private.pem.key","19c6c26982d07c36748cc182b65a711fb5e269aa88e8a29602afc93a12268b5a-certificate.pem.crt")
myClient.connect()

for i in range(10):
    message = str(i+1)
    myClient.publish("test/comp6733",message,1)
    print("Published: '"+ message + " to test/comp6733")
    t.sleep(0.5)

myClient.disconnect()