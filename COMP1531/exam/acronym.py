def acronym_make(inputs):
    if inputs == []:
        raise ValueError("No input")
    vowels = ['A', 'E', 'I', 'O', 'U', 'a', 'e', 'i', 'o', 'u']
    result = []
    for i in inputs:
        if i == '':
            raise ValueError("No input")
        acronym = ''
        for word in i.split(' '):
            if word[0] not in vowels:
                acronym += word[0]
        result.append(acronym.upper())
    return result

