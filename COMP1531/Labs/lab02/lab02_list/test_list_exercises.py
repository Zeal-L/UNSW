from list_exercises import reverse_list, minimum, sum_list

def test_reverse():
    l = ["how", "are", "you"]
    reverse_list(l)
    assert l == ["you", "are", "how"]
    l = ["1", "2", " ", "3"]
    reverse_list(l)
    assert l == ["3"," ", "2", "1"]
    l = [1, 2, 3, 4]
    reverse_list(l)
    assert l == [4, 3, 2, 1]

def test_min_positive():
    assert minimum([1, 2, 3, 10]) == 1
    assert minimum([-1, -2, -3, 1]) == 1
    assert minimum([99, 999, 9999, 1]) == 1

def test_sum_positive():
    assert sum_list([7, 7, 7]) == 21
    assert sum_list([7, -7, -7]) == 7
    assert sum_list([99, 999, 9999, 0]) == 11097

def test_sum_min_reverse():
    l = [-3, -2, -1, 0, 1, 2, 3]
    reverse_list(l)
    assert sum_list(l) + minimum(l) == 7
    l = [-3, -2, -1, 0, 1]
    reverse_list(l)
    assert sum_list(l) + minimum(l) == 2

