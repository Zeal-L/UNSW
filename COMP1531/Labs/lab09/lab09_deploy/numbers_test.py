from number_fun import multiply_by_two, print_message, sum_list_of_numbers, sum_iterable_of_numbers, is_in, index_of_number

'''
Sanity check tests.
'''

def test_multiply_by_two():
    assert multiply_by_two(2) == 4
    assert multiply_by_two(10) == 20

def test_print_message():
    print_message('COMP1531 is legit my favourite course ever')

def test_sum_list_of_numbers():
    assert sum_list_of_numbers([1,2,3,4]) == 10
    assert sum_list_of_numbers([]) == 0

def test_sum_iterable_of_numbers():
    assert sum_iterable_of_numbers([1,2,3,4]) == 10
    assert sum_iterable_of_numbers({1,2,3,4,5}) == 15
    assert sum_iterable_of_numbers((1,10,100,1000)) == 1111

def test_is_in():
    assert is_in(1, [1,2,3,4,5])
    assert not is_in('1', [1,2,3,4,5])
    assert is_in('a', ['a','b','c'])

def test_index_of_number():
    assert index_of_number(1, [1,2,3,4,5]) == 0
    assert index_of_number(6, [1,2,3,4,5]) is None
