from json import dumps
from flask import Flask, request

APP = Flask(__name__)

data_store = {
    'names':[]
}

def getData():
    global data_store
    return data_store

@APP.route('/name/add', methods=['POST'])
def add():
    data = getData()
    name = request.get_json()
    data['names'].append(name['name'])
    return dumps({})

@APP.route('/names', methods=['GET'])
def get_name():
    data = getData()
    return dumps(data)

@APP.route('/name/remove', methods=['DELETE'])
def remove():
    data = getData()
    to_remove = request.get_json()
    data['names'].remove(to_remove['name'])
    return dumps({})

@APP.route('/name/clear', methods=['DELETE'])
def clear():
    data = getData()
    data['names'] = []

if __name__ == '__main__':
    APP.run(port= 5000)