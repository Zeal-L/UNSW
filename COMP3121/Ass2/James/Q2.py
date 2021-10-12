def solution(A):
    n = len(A)
    A = sorted(A)
    num = 0
    unfis = 0
    hash = [0] * (max(A)+1)
    for i in A: hash[i] += 1
    print(hash)
    i = n-1
    while i > 0:
        a = A[i] - A[i-1] #距离下一个due还有多少天
        unfis += 1 #还有多少个任务
        if a >= 1 :
            if unfis == 1:
                i -= 1
                unfis -= 1
            elif a >= unfis: #如果距离下一个due可以完成所有任务
                num += (1+unfis)*unfis/2 #等差公式
                unfis = 0
            else:   #如果完不成
                num += (1+a)*a/2
                unfis -= a
            if a > 1:
                num -= 1
        else: 
            num += unfis
        print(unfis,num)
        i -= 1
    return [num,"can not complete"][unfis > 0];

A = [1,2,3,5,7,7,7]
print(solution(A))