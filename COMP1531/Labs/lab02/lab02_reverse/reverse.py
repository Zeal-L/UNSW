import re

def reverse_words(string_list):
    new = []
    for word in string_list:
        new.append("".join(re.split(r'(\s+)', word)[::-1]))
        #new.append(" ".join(list(reversed(word.split(' ')))))
    return new

if __name__ == "__main__":
    print(reverse_words(["Hello World", "I am here"]))
    # it should print ['World Hello', 'here am I']


