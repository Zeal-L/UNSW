import pytest
import requests

URL = 'http://127.0.0.1:5000'

@pytest.fixture
def setup():
    requests.delete(f'{URL}/clear')

def check_blackouts(actual, expected):
    DELTA = 2

    assert len(actual) == len(expected)
    for city in range(len(actual)):
        assert actual[city][0] == expected[city][0]
        assert actual[city][1] >= expected[city][1] - DELTA and actual[city][1] <= expected[city][1] + DELTA

def test_documentation(setup):
    requests.post(f'{URL}/city', json={'name': 'City1', 'theta': 2.827433388230814})
    requests.post(f'{URL}/city', json={'name': 'City2', 'theta': 0.9424777960769379})
    requests.post(f'{URL}/satellite', json={'height': 20183000.0, 'velocity': 3874.0, 'theta': 3.141592653589793})
    requests.post(f'{URL}/satellite', json={'height': 5100000.0, 'velocity': 5000.0, 'theta': 0.2345})

    response = requests.get(URL + '/simulate').json()
    expected = [('City1', 633), ('City2', 531)]
    cities = response['cities']

    check_blackouts(cities, expected)

def test_single_satellite(setup):
    requests.post(f'{URL}/city', json={'name': 'Vegas', 'theta': 1})
    requests.post(f'{URL}/city', json={'name': 'Sydney', 'theta': 2.5})
    requests.post(f'{URL}/satellite', json={'height': 20210000, 'velocity': 1000, 'theta': 3})

    response = requests.get(URL + '/simulate').json()
    expected = [('Sydney', 1073), ('Vegas', 1307)]
    cities = response['cities']

    check_blackouts(cities, expected)

def test_disco(setup):
    requests.post(f'{URL}/city', json={'name': 'city1', 'theta': 0})
    requests.post(f'{URL}/city', json={'name': 'city2', 'theta': 2.0943951024})
    requests.post(f'{URL}/city', json={'name': 'city3', 'theta': 4.1887902048})

    requests.post(f'{URL}/satellite', json={'height': 10000000, 'velocity': 9000, 'theta': 0})
    requests.post(f'{URL}/satellite', json={'height': 10000000, 'velocity': 9000, 'theta': 0.7853981634})
    requests.post(f'{URL}/satellite', json={'height': 10000000, 'velocity': 9000, 'theta': 1.5707963268})
    requests.post(f'{URL}/satellite', json={'height': 10000000, 'velocity': 9000, 'theta':  4.7123889804})

    response = requests.get(URL + '/simulate').json()
    expected = [('city1', 194), ('city2', 169), ('city3', 193)]
    cities = response['cities']

    check_blackouts(cities, expected)

def test_no_satellites(setup):
    requests.post(f'{URL}/city', json={'name': 'Perth', 'theta': 2.617993878})
    requests.post(f'{URL}/city', json={'name': 'Sydney', 'theta': 5.235987756})

    response = requests.get(URL + '/simulate').json()
    expected = [('Perth', 1440), ('Sydney', 1440)]
    cities = response['cities']

    check_blackouts(cities, expected)

def test_stationary_satellite(setup):
    requests.post(f'{URL}/city', json={'name': 'Perth', 'theta': 0})
    requests.post(f'{URL}/city', json={'name': 'Sydney', 'theta': 1.5707963268})
    requests.post(f'{URL}/satellite', json={'height': 2021202012021, 'velocity': 0, 'theta': 0})

    response = requests.get(URL + '/simulate').json()
    expected = [('Perth', 0), ('Sydney', 1440)]
    cities = response['cities']

    check_blackouts(cities, expected)
