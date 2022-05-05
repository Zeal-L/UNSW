#given a positive value p and a negative value q, fing Entropy
from math import log2
import json

def entropy(p,q):
    if p == 0 and q == 0: return 0
    elif p == 0: return -q*log2(q)
    elif q == 0: return -p*log2(p)
    else: return -p*log2(p)-q*log2(q)

if __name__ == '__main__':
    row_name = []
    num_name = 0
    while 1:
        name = input("Please input the row name: ")
        if name == "":
            break
        row_name.append(name)
        num_name += 1
    data = {}
    for i in row_name:
        data[i] = {}
        data[i]["data"] = []
        while 1:
            data_input = input(f"Please input the data for {i}, 格式 +空格-: ")
            if data_input == "":
                break
            data[i]["data"].append(list(map(int, data_input.split())))
    #查看输入的对不对
    num_postive = 0
    num_negative = 0
    for i in row_name:
        tmp_postive = 0
        tmp_negative = 0
        for j in data[i]["data"]:
            tmp_postive += int(j[0])
            tmp_negative += int(j[1])

        if num_postive != tmp_postive and num_postive != 0:
            print("输入有误，请重新输入")
            exit()
        if num_negative != tmp_negative and num_negative != 0:
            print("输入有误，请重新输入")
            exit()
        num_postive = tmp_postive
        num_negative = tmp_negative
    
    #计算熵
    for i in row_name:
        data[i]["entropy"] = 0
        for j in data[i]["data"]:
            j.append(0)
            numj = j[0] + j[1]
            j[-1] = entropy(j[0]/numj,j[1]/numj)
            data[i]["entropy"] += j[-1]*(numj/(num_postive + num_negative))
    
    total_entropy = entropy(num_postive/(num_postive + num_negative),num_negative/(num_postive + num_negative))
    for i in row_name:
        data[i]["information_gain"] = 0
        data[i]["information_gain"] = total_entropy - data[i]["entropy"]

    for i in row_name:
        print("-----------------------------------------------------------")
        print(f"the entropy fo {i} is: {round(data[i]['entropy'],3)}")
        print(f"the information gain fo {i} is: {round(data[i]['information_gain'],3)}")
        print("-----------------------------------------------------------")
    
    
    with open('data.json', 'w') as json_file: json_file.write(json.dumps(data))

'''
Please input the row name: size
Please input the row name: colour
Please input the row name: 
Please input the data for size, 格式 +空格-: 1 1
Please input the data for size, 格式 +空格-: 0 2
Please input the data for size, 格式 +空格-: 2 0
Please input the data for size, 格式 +空格-: 
Please input the data for colour, 格式 +空格-: 2 0
Please input the data for colour, 格式 +空格-: 1 1
Please input the data for colour, 格式 +空格-: 0 2
Please input the data for colour, 格式 +空格-: 
-----------------------------------------------------------
the entropy fo size is: 0.333
the information gain fo size is: 0.667
-----------------------------------------------------------
-----------------------------------------------------------
the entropy fo colour is: 0.333
the information gain fo colour is: 0.667
-----------------------------------------------------------
'''