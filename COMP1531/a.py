def foo():
    i = 0
    while i <= 9:
        if i % 3 == 0:
            print(i*2)
        else:
            print(i*3)
        i += 1
    print("done")

# pylint a.py --load-plugins=pylint.extensions.mccabe --max-complexity=0
