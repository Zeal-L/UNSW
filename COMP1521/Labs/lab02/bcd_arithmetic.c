#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>

//
// Store an arbitray length Binary Coded Decimal number
// bcd points to an array of size n_bcd
// each array element contains 1 decimal digit
//

typedef struct big_bcd {
    unsigned char *bcd;
    int n_bcd;
} big_bcd_t;


void bcd_print(big_bcd_t *number);
void bcd_free(big_bcd_t *number);
big_bcd_t *bcd_from_string(char *string);

big_bcd_t *expression(char ***tokens);
big_bcd_t *term(char ***tokens);

static void borrow(big_bcd_t *x, int j);

int main(int argc, char *argv[]) {
    char **tokens = argv + 1;

    // tokens points in turn to each of the elements of argv
    // as the expression is evaluated.

    if (*tokens) {
        big_bcd_t *result = expression(&tokens);
        bcd_print(result);
        printf("\n");
        bcd_free(result);
    }

    return 0;
}


// DO NOT CHANGE THE CODE ABOVE HERE


big_bcd_t *bcd_add(big_bcd_t *x, big_bcd_t *y) {
    int max_size = x->n_bcd > y->n_bcd ? x->n_bcd : y->n_bcd;
    unsigned char *sum = malloc(sizeof(char) * max_size);
    int temp = 0;

    for (int i = 0, j = 0, k = 0; i < max_size; i++) {
        if(j < x->n_bcd) temp += x->bcd[j++];
        if(k < y->n_bcd) temp += y->bcd[k++];
        sum[i] = temp % 10;
        temp /= 10;
    }
    // Reallocate memory if there is a carry bit
    if(temp == 1) {
        sum = realloc(sum, ++max_size);
        sum[max_size - 1] = 1;
    }

    big_bcd_t *result = malloc(sizeof *result);
    result->n_bcd = max_size;
    result->bcd = sum;
    return result;
}

big_bcd_t *bcd_subtract(big_bcd_t *x, big_bcd_t *y) {

    int max_size = x->n_bcd;
    unsigned char *sub = malloc(sizeof(char) * max_size);
    int temp = 0;

    for (int i = 0, j = 0, k = 0; i < max_size; i++) {
        if (j < x->n_bcd) temp = x->bcd[j++];
        if (k < y->n_bcd) {
            if (temp < y->bcd[k]) {
                borrow(x, j);
                temp = 10 + x->bcd[j-1] - y->bcd[k++];
            } else {
                temp -= y->bcd[k++];
            }
        }
        sub[i] = temp % 10;
        temp /= 10;
    }
    // Reallocate memory
    for (int i = max_size-1; i >= 0 ; i--) {
        if (sub[i] == 0) max_size--;
        if (sub[i] != 0) break;
    }
    if (max_size != x->n_bcd) sub = realloc(sub, max_size);

    big_bcd_t *result = malloc(sizeof *result);
    result->n_bcd = max_size;
    result->bcd = sub;
    return result;
}

static void borrow(big_bcd_t *x, int j) {
    if (x->bcd[j] != 0) {
        x->bcd[j] -= 1;
        return;
    }
    borrow(x, j+1);
    if (x->bcd[j+1] == 0 || x->bcd[j+1] == 9) {
        x->bcd[j] = 9;
    }
}
//  200
//  200
// 40000
// 完全失败
big_bcd_t *bcd_multiply(big_bcd_t *x, big_bcd_t *y) {

    big_bcd_t *mult = NULL;
    big_bcd_t *result = NULL;
    int times = 0;
    for (int i = 0; i < y->n_bcd; i++) {
        if (y->bcd[i] != 1) {
            for (int j = 0; j < y->bcd[i]-1; j++) {
                big_bcd_t *temp = mult;
                mult = bcd_add(x, x);
                if (temp != x && result != temp) bcd_free(temp);
            }
        }
        if (y->bcd[i] == 0) times++;
        if (i == 0) {
            if (y->bcd[i]) result = mult;
        } else if (mult) {
            if (i != 0) {
                for (int k = 0; k < times; k++) {
                    mult->n_bcd++;
                    for (int j = mult->n_bcd-1; j >= 0; j--) {
                        mult->bcd[j+1] = mult->bcd[j];
                    }
                }
                times = 0;
            }
            if (!result) {
                result = mult;
            } else {
                big_bcd_t *temp = result;
                result = bcd_add(result, mult);
                if (temp != x) bcd_free(temp);
            }
        }
    }
    return result;
}

big_bcd_t *bcd_divide(big_bcd_t *x, big_bcd_t *y) {
    // PUT YOUR CODE HERE
    return NULL;
}


// DO NOT CHANGE THE CODE BELOW HERE


// print a big_bcd_t number
void bcd_print(big_bcd_t *number) {
    // if you get an error here your bcd_arithmetic is returning an invalid big_bcd_t
    assert(number->n_bcd > 0);
    for (int i = number->n_bcd - 1; i >= 0; i--) {
        putchar(number->bcd[i] + '0');
    }
}


// DO NOT CHANGE THE CODE BELOW HERE

// free storage for big_bcd_t number
void bcd_free(big_bcd_t *number) {
    // if you get an error here your bcd_arithmetic is returning an invalid big_bcd_t
    // or it is calling free for the numbers it is given
    free(number->bcd);
    free(number);
}

// convert a string to a big_bcd_t number
big_bcd_t *bcd_from_string(char *string) {
    big_bcd_t *number = malloc(sizeof *number);
    assert(number);

    int n_digits = strlen(string);
    assert(n_digits);
    number->n_bcd = n_digits;

    number->bcd = malloc(n_digits * sizeof number->bcd[0]);
    assert(number->bcd);

    for (int i = 0; i < n_digits; i++) {
        int digit = string[n_digits - i - 1];
        assert(isdigit(digit));
        number->bcd[i] = digit - '0';
    }

    return number;
}


// simple recursive descent evaluator for  big_bcd_t expressions
big_bcd_t *expression(char ***tokens) {

    big_bcd_t *left = term(tokens);
    assert(left);

    if (!**tokens|| (***tokens != '+' && ***tokens != '-')) {
        return left;
    }

    char *operator = **tokens;
    (*tokens)++;

    big_bcd_t *right = expression(tokens);
    assert(right);

    big_bcd_t *result;
    if (operator[0] == '+') {
        result = bcd_add(left, right);
    } else {
        assert(operator[0] == '-');
        result = bcd_subtract(left, right);
    }
    assert(result);

    bcd_free(left);
    bcd_free(right);
    return result;
}


// evaluate a term of a big_bcd_t expression
big_bcd_t *term(char ***tokens) {

    big_bcd_t *left = bcd_from_string(**tokens);
    assert(left);
    (*tokens)++;

    if (!**tokens || (***tokens != '*' && ***tokens != '/')) {
        return left;
    }

    char *operator = **tokens;
    (*tokens)++;

    big_bcd_t *right = term(tokens);
    assert(right);

    big_bcd_t *result;
    if (operator[0] == '*') {
        result = bcd_multiply(left, right);
    } else {
        result = bcd_divide(left, right);
    }
    assert(result);

    bcd_free(left);
    bcd_free(right);
    return result;
}
