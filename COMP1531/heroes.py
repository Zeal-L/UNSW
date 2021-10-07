from json import dumps
from flask import Flask, request

APP = Flask(__name__)

class Hero:
    def __init__(self, id, name, power):
        self.id = id
        self.name = name
        self.power = power

heroes = []

@APP.route('/heroes', methods=['GET'])
def get_all_heroes():
    return dumps([hero.__dict__ for hero in heroes])

@APP.route('/heroes/<id>', methods=['GET'])
def get_hero_by_id(id):
    requested_id = int(id)
    for hero in heroes:
        if hero.id == requested_id:
            return dumps(hero.__dict__)
    return dumps({})

@APP.route('/heroes/<id>', methods=['DELETE'])
def delete_hero_by_id(id):
    requested_id = int(id)
    for hero in heroes:
        if hero.id == requested_id:
            removed_hero = hero
            heroes.remove(hero)
            return dumps(removed_hero.__dict__)
    return dumps({})

@APP.route('/heroes', methods=['POST'])
def post_new_hero():
    request_data = request.get_json()
    new_hero = Hero(len(heroes), request_data['name'], request_data['power'])
    heroes.append(new_hero)
    return dumps(new_hero.__dict__)

if __name__ == '__main__':
    heroes.append(Hero(0, "Superman", "Super Strength"))
    heroes.append(Hero(1, "Wonder Woman", "Super Strength"))
    heroes.append(Hero(2, "Zeal", "Super Super Strength"))
    APP.run(port=2000)