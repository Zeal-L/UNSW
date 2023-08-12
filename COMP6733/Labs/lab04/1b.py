import sys
import asyncio
import platform
import numpy as np

from bleak import BleakClient
from bleak import BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic


################################################################

import time as t
import json
import AWSIoTPythonSDK.MQTTLib as AWSIoTpyMQTT

# Client configuration with endpoint and credentials
myClient = AWSIoTpyMQTT.AWSIoTMQTTClient("testDevice")
myClient.configureEndpoint("aiy0i9khf86c-ats.iot.us-east-1.amazonaws.com", 8883)
myClient.configureCredentials(
    "AmazonRootCA1.pem",
    "19c6c26982d07c36748cc182b65a711fb5e269aa88e8a29602afc93a12268b5a-private.pem.key",
    "19c6c26982d07c36748cc182b65a711fb5e269aa88e8a29602afc93a12268b5a-certificate.pem.crt",
)
myClient.connect()

################################################################

ADDRESS = "C5:CE:33:69:CD:58"

custom_svc_uuid = "4A981234-1CC4-E7C1-C757-F1267DD021E8"
custom_wrt_char_uuid = "4A981235-1CC4-E7C1-C757-F1267DD021E8"
custom_read_char_uuid = "4A981236-1CC4-E7C1-C757-F1267DD021E8"


async def scan():
    print("scanning for 5 seconds, please wait...")
    devices = await BleakScanner.discover(return_adv=True)
    for d, a in devices.values():
        print("\n", d)
        print("-" * len(str(d)))
        print(a)


async def ReadandWrite():
    def handle_rx(_: BleakGATTCharacteristic, data: bytearray):
        myClient.publish(
            "test/comp6733",
            json.dumps(
                {
                    "time": t.time(),
                    "humidity": data.decode("utf-8"),
                }
            ),
            1,
        )
        print(f"Published: '{data} to test/comp6733")

    def handle_write():
        data = sys.stdin.buffer.readline().strip()
        return data

    async with BleakClient(ADDRESS, use_cached=False) as client:
        print(f"Connected: {client.is_connected}")

        await client.start_notify(custom_read_char_uuid, handle_rx)
        print("Connected, start typing and press ENTER...")
        loop = asyncio.get_running_loop()
        custom_svc = client.services.get_service(custom_svc_uuid)
        wrt_char = custom_svc.get_characteristic(custom_wrt_char_uuid)

        while True:
            # This waits until you type a line and press ENTER.
            # A real terminal program might put stdin in raw mode so that things
            # like CTRL+C get passed to the remote device.
            data = await loop.run_in_executor(None, handle_write)
            # data will be empty on EOF (e.g. CTRL+D on *nix)
            if not data:
                break
            await client.write_gatt_char(wrt_char, data)
            print("sent:", data)


if __name__ == "__main__":
    asyncio.run(ReadandWrite())
