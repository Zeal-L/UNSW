def solution(A,k):
    m = max(A)/2
    hf = m
    n = len(A)
    A = sorted(A)
    ans1 = []
    ans = [A[0]] # 因为不管间隔为多少，只要A[0]必是答案的其中一个
    while hf >= 1:
        hf = round(hf / 2)
        i = 1
        j = 0
        while i < n:
            if A[i] - A[j] >= m:
                # 将A[i] 和 A[j]的位置进行对比，如果间隔大于m，就说明A[i]为答案，
                # 那么就将i和j调换位置，比如说1 2 6 9，
                # 那么我们在间隔为3的情况下可以查到1 6，最后接着6可以查到9，ans里面的数据即为1 6 9
                ans.append(A[i])
                if len(ans) >= k: break
                #如果此数组长度符合题目要求，就没有必要继续循环
                j = i
            i+=1
        if len(ans) >= k:
            # 数组A中存在给予当前m的长度为k的数组，
            # 那么则将此答案复制到数组ans1中，
            # 并将m加上hf（符合O（nlogn）算法），尽可能让m大
            # 比如说 m=10,m在最开始已经被除以2，因为A中不可能存在比m大的间隔，所以m现在等于5，
            # 如果间隔为5长度为k的sub在A中时存在的，那么就将5 + 5/2（四舍五入） = 8
            # 如果间隔为8长度为k的sub在A中不存在，那么就将8 - 5/2/2 = 7
            # 如果7 是存在的，那么就7即为答案，因为5/2/2/2现在已经小于0，不可再分
            ans1 = ans
            m += hf
        else: m -= hf
            # 每次重制数组ans
        ans = [A[0]]
    return ans1
A = [1,5,3,8,9,2]
print(sorted(A))
print(solution(A,4))