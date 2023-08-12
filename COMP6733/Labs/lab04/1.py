import time
from ubluepy import Service, Characteristic, UUID, Peripheral, constants
from machine import Timer
import hs3003
from machine import Pin, I2C
bus = I2C(1, scl=Pin(15), sda=Pin(14))
hs = hs3003.HS3003(bus)

def send_humidity(t):
    global custom_read_char

    rH = hs.humidity()
    time.sleep_ms(100)
    msg = "%.2f%%" % hs.humidity()
    print("send: ", msg)
    custom_read_char.write(msg)

def event_handler(id, handle, data):
    global periph
    global services
    global custom_read_char
    global notif_enabled
    if id == constants.EVT_GAP_CONNECTED:
        pass
    elif id == constants.EVT_GAP_DISCONNECTED:
        # restart advertisement
        periph.advertise(device_name="Zeal's Nano 33 BLE Sense")
    elif id == constants.EVT_GATTS_WRITE:
        if handle == 16:  # custom_wrt_char
            if notif_enabled:
                tim = Timer(
                    2,
                    period=2000000,
                    mode=Timer.PERIODIC,
                    callback=send_humidity,
                )
                tim.start()

        elif handle == 19:  # CCCD of custom_read_char
            if int(data[0]) == 1:
                notif_enabled = True
            else:
                notif_enabled = False


notif_enabled = False

custom_svc_uuid = UUID("4A981234-1CC4-E7C1-C757-F1267DD021E8")
custom_wrt_char_uuid = UUID("4A981235-1CC4-E7C1-C757-F1267DD021E8")
custom_read_char_uuid = UUID("4A981236-1CC4-E7C1-C757-F1267DD021E8")

custom_svc = Service(custom_svc_uuid)
custom_wrt_char = Characteristic(custom_wrt_char_uuid, props=Characteristic.PROP_WRITE)
custom_read_char = Characteristic(
    custom_read_char_uuid,
    props=Characteristic.PROP_READ | Characteristic.PROP_NOTIFY,
    attrs=Characteristic.ATTR_CCCD,
)
custom_svc.addCharacteristic(custom_wrt_char)
custom_svc.addCharacteristic(custom_read_char)

periph = Peripheral()
periph.addService(custom_svc)
periph.setConnectionHandler(event_handler)
periph.advertise(device_name="Zeal's Nano 33 BLE Sense")

while True:
    time.sleep_ms(500)
