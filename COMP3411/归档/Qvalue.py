#导入sympy
from sympy import *

def seteq(δ,r,γ):
    eqs = {}
    sym = {}
    for i in δ.keys():
        if i[0] != δ[i]:
            sym[i[0]] = Symbol(i[0])
            sym[δ[i]] = Symbol(δ[i])
    if sym == {}:
        print('无变量')
        exit()
    for i in δ.keys():
        if i[0] == δ[i]:
            eqs[i] = r[i]+(γ-1)*sym[δ[i]]
        else:
            eqs[i] = r[i]+γ*sym[δ[i]]-sym[i[0]]
    k = list(eqs.keys())
    l = int(len(k)/2)
    solved = {}
    for i in range(l):
        for j in range(l):
            solved[k[i],k[j+l]] = solve([eqs[k[i]],eqs[k[j+l]]],sym["S1"],sym["S2"])
    
    max = 0
    #print(solved)
    for i in solved.keys():
        num = 0
        for j in solved[i]:
            num += solved[i][j]
        if num > max:
            max = num
            maxi = i

    Q = {}
    #Q[maxi] = solved[maxi] π

    for i in maxi:
        print(f"π*({i[0]}) = {i[1]}")
    for i in range(len(maxi)):
        Q[maxi[i]] = solved[maxi][list(solved[maxi].keys())[i]]
    for i in r.keys():
        if i not in maxi:
            Q[i] = γ*solved[maxi][sym[δ[i]]]+r[i]

    #print Q as a fromat
    for i in sorted(list(Q.keys())):
        if i in maxi:
            print(f"\033[91m{i},{Q[i]}\033[0m")
        else:
            print(f"{i},{Q[i]}")
    return Q

δ = {}
δ["S1","a1"] = "S1"
δ["S1","a2"] = "S2"
δ["S2","a1"] = "S2"
δ["S2","a2"] = "S1"
r = {}
r["S1","a1"] = 0
r["S1","a2"] = -1
r["S2","a1"] = 1
r["S2","a2"] = 5
γ = 0.9

seteq(δ,r,γ)