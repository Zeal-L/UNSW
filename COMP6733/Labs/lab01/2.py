from board import LED
import time

led_red = LED(1)
led_green = LED(2)
led_blue = LED(3)
led_builtin = LED(4)

leds_count = 0

led_builtin_count = 0
led_builtin_state = True

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

    leds_count += 100
    led_builtin_count += 100
    time.sleep_ms(100)