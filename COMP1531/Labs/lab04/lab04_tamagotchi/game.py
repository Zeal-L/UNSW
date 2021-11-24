from tamagotchi import Tamagotchi

all_pet = {}

while True:
    command = input("Command: ").split(' ')
    if command[0] == 'create':
        if command[1] in all_pet.keys():
            if not all_pet[command[1]].is_dead():
                print('You already have a Tamagotchi called that.')
                continue
        all_pet[command[1]] = Tamagotchi(command[1])

    elif command[0] == 'feed':
        if command[1] not in all_pet.keys():
            print('No Tamagotchi with that name.')
            continue
        elif not all_pet[command[1]].is_dead():
            all_pet[command[1]].feed()
        else:
            continue
    elif command[0] == 'play':
        if command[1] not in all_pet.keys():
            print('No Tamagotchi with that name.')
            continue
        elif not all_pet[command[1]].is_dead():
            all_pet[command[1]].play()
        else:
            continue
    elif command[0] == 'wait':
        pass
    elif command[0] == '':
        break
    else:
        print('Invalid command.')
        continue

    print("")
    for key in sorted(all_pet):
        print(all_pet[key])
        all_pet[key].increment_time()
print("")
