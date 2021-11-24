# Tamagotchi ASCII art.
SMALL = r'''

 _____
/ ^_^ \
\_____/
'''[1:-1]
MED = r'''
   _______
  /       \
 /  ^ _ ^  \
 \_________/
    U   U
'''[1:-1]
BIG = r'''
   ___________
  /           \
 /  /\     /\  \
 \      _      /
  \___________/
    \_/   \_/
'''[1:-1]


class Tamagotchi:
    """
    Represents a single Tamagotchi pet.
    """
    def __init__(self, name):
        """
        Given a name, initialises a Tamagotchi as though born with basic stats.
        """
        self.__name = name
        self.__is_dead = False
        self.__age = 0
        self.__hunger = 5
        self.__boredom = 0

    def is_dead(self):
        """
        Returns True if the Tamagotchi is dead, False otherwise.
        """
        return self.__is_dead

    def feed(self):
        """
        Decreases the Tamagotchi's hunger level.
        """
        if self.is_dead():
          return

        self.__hunger -= 3

        # Check for overfeeding.
        if self.__hunger < 0:
          self.__hunger = 0
          self.__is_dead = True

    def play(self):
        """
        Decreases the Tamagotchi's boredom level.
        """
        if self.is_dead():
          return

        self.__boredom -= 5
        if self.__boredom < 0:
            self.__boredom = 0

    def increment_time(self):
        """
        Adjusts stats as though time has passed for this tamagotchi.
        """
        if self.is_dead():
            return

        self.__hunger += 1
        self.__age += 1
        self.__boredom += 1

        if self.__age > 15:
            self.__is_dead = True

        if self.__hunger > 10:
            self.__is_dead = True

        if self.__boredom > 10:
            self.__is_dead = True

    def __str__(self):
        """
        Returns a string representing the current status of the tamagotchi.
        """
        if self.is_dead():
          return '''
Name:    {}
DEAD
        '''.format(self.__name)

        if self.__age < 3:
            picture = SMALL
        elif self.__age < 6:
            picture = MED
        else:
            picture = BIG
        return '''{}
Name:    {}
Hunger:  {}
Boredom: {}
Age:     {}
        '''.format(picture, self.__name,
                  (self.__hunger * 'o' if self.__hunger else ''),
                  (self.__boredom * 'o' if self.__boredom else ''),
                  self.__age)
