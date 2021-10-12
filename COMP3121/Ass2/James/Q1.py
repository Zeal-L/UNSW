def solution(a):
    i = 0
    while i < len(a):
        if i != 0:
            if a[i] <= a[i-1]:
                print(a)
                print("No solution")
                return
        num = a[i] - i - 1
        if i != len(a) - 1:
            a[i] -= num
            a[i+1] += num
        print(a)
        i+=1
    print(a)

a = [1,9,4,3]

# solution(a)
solution([3,2,1,4])