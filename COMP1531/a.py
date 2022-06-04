def checkInclusion(s1, s2):
    m1 = len(s1)
    m2 = len(s2)
    if m1 > m2:
        return False
    dic1 = [0]*26
    dic2 = [0]*26
    for i in range(m1):
        dic1[ord(s1[i])-ord('a')] += 1
        dic2[ord(s2[i])-ord('a')] += 1
    if dic1 == dic2:
        return True

    for i in range(m1,m2):
        dic2[ord(s2[i-m1])-ord('a')] -= 1
        dic2[ord(s2[i])-ord('a')] += 1
        if dic1 == dic2:
            return True
    return False

print(checkInclusion("ab","eidbaooo"))

checkInclusion("hello",
"ooolleoooleh")