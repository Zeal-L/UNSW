import copy

def slo(A,m):
    n = len(A)
    ans = [[[0] for i in range(m)] for j in range(n)]
    max_ = [0 for i in range(n)]
    i = 0
    while i < n:
        j = 0
        crr = []
        while j < m:
            if i == 0 and A[i][j] == 1: 
                ans[i][j] = [i+1]
                crr.append(copy.deepcopy(ans[i][j]))
            elif ans[i-1][j] == [0] and A[i][j] == 1:
                arr = [i + 1]
                ans[i][j] = []
                ans[i][j] = copy.deepcopy(arr)
                crr.append(copy.deepcopy(ans[i][j]))
            elif A[i][j] == 1:
                ans[i][j] = copy.deepcopy(max_[(ans[i-1][j][-1]-1)])
                ans[i][j].append(i+1)
                crr.append(copy.deepcopy(ans[i][j]))
            else:
                ans[i][j] = copy.deepcopy(ans[i-1][j])
            j += 1
        if len(max(crr, key = len)) == 1:
            max_[i] = copy.deepcopy(max(crr))
        else:
            max_[i] = max(crr, key = len)
        i += 1
    print(ans)
    
A = [[0,1,0,1],
     [1,0,1,1],
     [0,0,1,0],
     [1,1,0,1],
     [0,0,1,1]]

slo(A,4)
    