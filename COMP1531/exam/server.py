'''
The flask server wrapper

All endpoints return JSON as output.
All POST requests pass parameters through JSON instead of Form.
'''
from json import dumps
from flask import Flask, request
from config import port

import trouble

APP = Flask(__name__)

'''
Endpoint: '/clear'
Method: POST
Parameters: {}
Output: {}

Resets the state of the server. Please implement this as we use it during marking.
'''

# Write the endpoint here
@APP.route("/clear", methods=['POST'])
def clear():
    trouble.clear()
    return dumps({})


'''
Endpoint: '/flip_card'
Method: POST
Parameters: {"suit": String, "number": Integer}
Output: {}

Calls the underlying flip card function to implement it's behaviour
'''

# Write this endpoint here
@APP.route("/flip_card", methods=['POST'])
def flip_card():
    data = request.get_json()
    trouble.flip_card(data)
    return dumps({})

'''
Endpoint: '/is_double_trouble'
Method: GET
Parameters: {}
Output: { "result": Boolean }

Returns true if the last two cards were the same number. False otherwise.
If this function is called whilst true, the pile is reset to empty.
'''

# Write the endpoint here
@APP.route("/is_double_trouble", methods=['GET'])
def is_double_trouble():
    resp = trouble.is_double_trouble()
    return dumps({"result": resp})

'''
Endpoint: '/is_trouble_double'
Method: GET
Parameters: {}
Output: { "result": Boolean }

Returns true if the last four cards had the same suit. False otherwise.
If this function is called whilst true, the pile is reset to empty.
'''

# Write the endpoint here
@APP.route("/is_trouble_double", methods=['GET'])
def is_trouble_double():
    resp = trouble.is_trouble_double()
    return dumps({"result": resp})

'''
Endpoint: '/is_empty'
Method: GET
Parameters: {}
Output: { "result": Boolean }

Returns a boolean that is true if the pile of cards is empty, false if it is not empty
'''

# Write the endpoint here
@APP.route("/is_empty", methods=['GET'])
def is_empty():
    resp = trouble.is_empty()
    return dumps({"result": resp})



if __name__ == '__main__':
    APP.run(debug=True, port=port)
