import json
import operator
import pickle

def most_common():
    f = open('shapecolour.p', 'rb')

    unpickle = pickle.load(f)
    counter = {}
    for pair in unpickle:
        key = pair['colour'] + ' ' + pair['shape']
        counter[key] = counter.get(key, 0) + 1

    m_common = max(counter.keys(), key=(lambda x:counter[x]))
    m_common = m_common.split(' ')
    return {
        "colour": m_common[0],
        "shape": m_common[1]
    }

def process():
    m_common = most_common()
    result = {}
    result["mostCommon"] = m_common
    result["rawData"] = [pickle.load(open('shapecolour.p', 'rb'))]

    f = open('processed.json', 'w')
    json.dump(result, f)


process()