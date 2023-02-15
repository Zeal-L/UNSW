# import math

# def solution(A):
#     """
#     You are given a sequence A = ⟨A[1],…,A[n]⟩ of n distinct positive
#     integers. A subsequence B of A is said to be distant if no two consecutive
#     elements of A, say A[i] and A[i + 1], both belong to B.
#     Design an algorithm which finds the largest possible sum of elements of
#     a distant subsequence and runs in O(n) time.
#     You must provide reasoning to justify the correctness and time complexity of
#     your algorithm.
#     The input consists of a positive integer n, as well as n distinct positive
#     integers A[1],…,A[n].
#     The output is the largest possible sum of elements of a distant subsequence.
#     Note that you do not need to find a subsequence which achieves this sum.
#     For example, if the sequence is ⟨2, 5, 1, 3, 4⟩, the correct answer is 9.
#     """

#     pass
#     n = len(A)
#     if n < 2:
#         return 0
#     dp = [0] * n
#     dp[0] = A[0]
#     dp[1] = max(A[0], A[1])
#     for i in range(2, n):
#         dp[i] = max(dp[i - 2] + A[i], dp[i - 1])
#     return dp[-1]



# print(solution([2, 5, 1, 3, 4]))
