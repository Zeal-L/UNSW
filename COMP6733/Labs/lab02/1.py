import time
import hs3003
from machine import Pin, I2C
import lps22h
from machine import Timer

bus = I2C(1, scl=Pin(15), sda=Pin(14))

def temp_humi(t):
    hs = hs3003.HS3003(bus)
    temp = hs.temperature()
    time.sleep_ms(100)
    print("rH: %.2f%% T: %.2fC" % (hs.humidity(), hs.temperature()))
        
def pressure(t):
    lps = lps22h.LPS22H(bus)
    print("Pressure: %.2f hPa" % lps.pressure())

tim1 = Timer(1, period=333333, mode=Timer.PERIODIC, callback=temp_humi)
tim1.start()

tim2 = Timer(2, period=1000000, mode=Timer.PERIODIC, callback=pressure)
tim2.start()
