import time
from ubluepy import Service, Characteristic, UUID, Peripheral, constants
from board import LED
from machine import Timer

led_red = LED(1)
led_green = LED(2)
led_blue = LED(3)
led_builtin = LED(4)


def event_handler(id, handle, data):
    global periph
    global services
    global custom_read_char

    if id == constants.EVT_GAP_CONNECTED:
        pass
    elif id == constants.EVT_GAP_DISCONNECTED:
        # restart advertisement
        periph.advertise(device_name="Zeal's Nano 33 BLE Sense")
        print("restaring...")
    elif id == constants.EVT_GATTS_WRITE:
        if handle == 16:  # custom_wrt_char
            if data == "r":
                tim = Timer(
                    1,
                    period=2000000,
                    mode=Timer.PERIODIC,
                    callback=lambda t: led_red.toggle(),
                )
                tim.start()
            elif data == "g":
                tim = Timer(
                    2,
                    period=2000000,
                    mode=Timer.PERIODIC,
                    callback=lambda t: led_green.toggle(),
                )
                tim.start()
            elif data == "b":
                tim = Timer(
                    3,
                    period=2000000,
                    mode=Timer.PERIODIC,
                    callback=lambda t: led_blue.toggle(),
                )
                tim.start()


custom_svc_uuid = UUID("4A981234-1CC4-E7C1-C757-F1267DD021E8")
custom_wrt_char_uuid = UUID("4A981235-1CC4-E7C1-C757-F1267DD021E8")

custom_svc = Service(custom_svc_uuid)  # handle = handle + 1 (service)
custom_wrt_char = Characteristic(
    custom_wrt_char_uuid, props=Characteristic.PROP_WRITE
)  # char = 2
custom_svc.addCharacteristic(custom_wrt_char)  # handle = handle + char

periph = Peripheral()
periph.addService(custom_svc)
periph.setConnectionHandler(event_handler)
periph.advertise(device_name="Zeal's Nano 33 BLE Sense")

while True:
    time.sleep_ms(500)
