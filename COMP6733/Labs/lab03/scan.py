import sys
import asyncio
import platform
import numpy as np

from bleak import BleakClient
from bleak import BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic

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


async def scanMyRSSI():
    print("scanning for 5 seconds, please wait...")
    while True:
        devices = await BleakScanner.discover(return_adv=True)
        for d, a in devices.values():
            if d.address == ADDRESS:
                print("RSSI:", d.rssi)
                # pathloss = [-0.01719958 -0.53701318]
                print("distance:", (d.rssi + 0.53701318) / -0.01719958)
                # print("distance:", np.polyval(pathloss, device.rssi))


async def connect():
    async with BleakClient(ADDRESS) as client:
        print(f"Connected: {client.is_connected}")
        await asyncio.sleep(5.0)
        print("disconnected")


async def ReadandWrite():
    def handle_rx(_: BleakGATTCharacteristic, data: bytearray):
        print("received:", data)

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
