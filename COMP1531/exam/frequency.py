def frequency_get(multilinestr):
    table = ".?!,;:()[]{}-"
    new = ''
    for i in multilinestr:
        if i not in table:
            new += i

    new = new.split()
    freq = {}
    for i in new:
        if i in freq:
            freq[i] += 1
        else:
            freq[i] = 1
    freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    output = ''
    for i in freq:
        output += i[0].upper() + ': ' + str(i[1]) + '\n'
    return output.strip('\n')

