def q2_solution(a,m):
    answer = []
    occurrence = [0] * (m+1) # hash table A
    times = [0] * (len(a)+1) # hash table B
    times[0] = m
    curr_beauty = 0

    for i in a:
        times[occurrence[i]] -= 1
        occurrence[i] += 1
        times[occurrence[i]] += 1
        if times[curr_beauty] == 0:
            curr_beauty += 1
        answer.append(curr_beauty)

    print(answer)
    print("All fulfilling indices:")
    for i, _ in enumerate(answer):
        if answer[i] > answer[i-1]:
            print(i, end=' ')

q2_solution([1,3,1,2,3,3,2,3],3)

# Output
# [0, 0, 0, 1, 1, 1, 2, 2]
# All fulfilling indices:
# 3 6
