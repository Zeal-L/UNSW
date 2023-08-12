from board import LED
import time

led_red = LED(1)
led_green = LED(2)
led_blue = LED(3)
led_builtin = LED(4)

while True:
    led_builtin.on()
    time.sleep_ms(700)
    led_builtin.off()
    time.sleep_ms(300)
