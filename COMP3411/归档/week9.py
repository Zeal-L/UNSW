x = [[0,2], #第一列
    [1,0]]  #第二列
Class = [-1,-1]
w = [-0.5,0,1]
learning_rate = 0.5



num_none = 0
example = 0
itera = 1
while True:
    if example == len(x[0]):
        example = 0
    predi = 0

    for i in range(len(x)):
        predi += w[i+1]*x[i][example]

    predi += w[0]
    tClass = Class[example]
    print(str(itera).rjust(3), str(w).ljust(18), str(example+1).ljust(5)," | ", end="")
    for i in x:
        print(str(i[example]).ljust(5), end="")
    print("| ",str(Class[example]).ljust(5), str(predi).ljust(5), str([-1,1][predi > 0]).ljust(3), str([["Subtract","Add"][predi < 0],"None"][(predi < 0 and tClass < 0) or (predi > 0 and tClass > 0)]).ljust(3))
    
    if (predi < 0 and tClass < 0) or (predi > 0 and tClass > 0):
        example += 1
        num_none += 1
        if num_none == len(x[0]):
            break
    else:
        w[0] = w[0] + learning_rate*tClass
        for i in range(len(x)):
            w[i+1] = w[i+1] + learning_rate*tClass*x[i][example]
        example += 1
        num_none = 0
    itera += 1