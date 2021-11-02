def slo(arr,m):
    ma = [False for i in range(m)]
    for i in arr:
        ma[i] = True
        crr = [[False] for p in range(m)]
        #可以确定肯定存在合为i的点
        crr[i] = True
        j = 0
        while j < m:
            if ma[j] == True:
                #遇见之前的和，加上当前的i，这个点也是肯定存在的
                if j + i < m:
                    crr[j + i] = True
            j += 1
        l = 0
        while l < len(crr):
            #吧crr数组里面位true的给复制到数组ma里面
            if crr[l] == True: ma[l] = True
            l += 1
    print(ma)

slo([1,2,3,4,5],15)