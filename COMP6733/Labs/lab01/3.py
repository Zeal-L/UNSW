from board import LED
import time

import hs3003
from machine import Pin, I2C
bus = I2C(1, scl=Pin(15), sda=Pin(14))
hs = hs3003.HS3003(bus)

led_red = LED(1)
led_green = LED(2)
led_blue = LED(3)
led_builtin = LED(4)

leds_count = 0

led_builtin_count = 0
led_builtin_state = True

temperature_count = 0

rH = hs.humidity()
temp = hs.temperature()
time.sleep_ms(100)

while True:
    if led_builtin_count == 700 and led_builtin_state:
        led_builtin.off()
        led_builtin_count = 0
        led_builtin_state = False
    elif led_builtin_count in [0, 300] and not led_builtin_state:
        led_builtin.on()
        led_builtin_count = 0
        led_builtin_state = True
        
    if leds_count == 0:
        led_red.on()
    elif leds_count == 1100:
        led_green.on()
    elif leds_count == 2200:
        led_blue.on()
    elif leds_count == 3300:
        led_blue.off()
    elif leds_count == 4200:
        led_green.off()
    elif leds_count == 5100:
        led_red.off()
    elif leds_count == 6000:
        leds_count = 0
        continue
    rH = hs.humidity()
    temp = hs.temperature()
    if temperature_count % 1700 == 0:
        print ("rH: %.2f%% T: %.2fC" %(hs.humidity(), hs.temperature()))
    
    leds_count += 100
    led_builtin_count += 100
    temperature_count += 100
    time.sleep_ms(100)
