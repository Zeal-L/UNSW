// By Zeal L, September 2020 Secend week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    char words[11][10] = {"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"};
    int number_1 = 0, number_2 = 0;
    printf("Please enter two integers: ");
    scanf("%d%d", &number_1, &number_2);
    int sum = number_1 + number_2, p_n_sum = 1, p_n_1 = 1, p_n_2 = 1;  //p_n means positive and negative
    if (sum < 0) { //Determine if the variable is negative and save it in advance
        sum = sum * -1;
        p_n_sum = 0;
    } 
    if (number_1 < 0) {
        number_1 = number_1 * -1;
        p_n_1 = 0;
    }
    if (number_2 < 0) {
        number_2 = number_2 * -1;
        p_n_2 = 0;
    } 
    if (number_1 >= -10 && number_1 <= 10) { //Judge the case of different variables, then output it respectively
        if (p_n_1 == 0) {
            printf("negative %s + ", words[number_1]);
        } else {
            printf("%s + ", words[number_1]);
        }
    } else {
        printf("%d + ", number_1);
    }
    if (number_2 >= -10 && number_2 <= 10) {
        if (p_n_2 == 0) {
            printf("negative %s = ", words[number_2]);
        } else {
            printf("%s = ", words[number_2]);
        }
    } else {
         printf("%d = ", number_2);
    }
    if (sum >= -10 && sum <= 10) {
        if (p_n_sum == 0) {
            printf("negative %s\n", words[sum]);
        } else {
            printf("%s\n", words[sum]);
        }
    } else {
        printf("%d\n", sum);
    }
    return 0;
}
    

    /*The following code is my first try, in a stupid way...
     // while (count_1 != number_1) { //Determine the position of the number corresponding to the array
    // if (number_1 >= -10 && number_1 <= 10) {
    //         if (number_1 < 0) {
    //             number_1 = number_1 * -1;
    //     }
    //         count_1++;
    //     } else { //Don't need to use word if the variable is beyond (-10,10)
    //         count_1 = number_1;
    //     }
    // }
    // while (count_2 != number_2) {
    //     if (number_2 >= -10 && number_2 <= 10) {
    //         if (number_2 < 0) {
    //             number_2 = number_2 * -1;
    //     }
    //         count_2++;
    //     } else {
    //         count_2 = number_2;
    //     }
    // }
    // while (count_sum != sum) {
    //     if (sum >= -10 && sum <= 10) {
    //         if (sum < 0) {
    //         sum = sum * -1;
    //     }
    //         count_sum++;
    //     } else {
    //         count_sum = sum;
    //     }
    // }

     if (count_sum >= -10 && count_sum <= 10) {
         if (count_1 >= -10 && count_1 <= 10) {
             if (count_2 >= -10 && count_2 <= 10) {
                 if (p_n_1 == 0) {
                     if (p_n_2 == 0) {
                        if (p_n_sum == 0) {
                            printf("negative %s + negative %s = negative %s\n", words[count_1], words[count_2], words[count_sum]);
                         } else {
                             printf("negative %s + negative %s = %s\n", words[count_1], words[count_2], words[count_sum]);
                         }
                     } else if (p_n_sum == 0) {
                         printf("negative %s + %s = negative %s\n", words[count_1], words[count_2], words[count_sum]);
                     } else {
                         printf("negative %s + %s = %s\n", words[count_1], words[count_2], words[count_sum]);
                     }
                } else {
                    if (p_n_2 == 0) {
                            if (p_n_sum == 0) {
                                printf("%s + negative %s = negative %s\n", words[count_1], words[count_2], words[count_sum]);
                            } else {
                                printf("%s + negative %s = %s\n", words[count_1], words[count_2], words[count_sum]);
                            }
                        } else if (p_n_sum == 0) {
                            printf("%s + %s = negative %s\n", words[count_1], words[count_2], words[count_sum]);
                        } else {
                            printf("%s + %s = %s\n", words[count_1], words[count_2], words[count_sum]);
                        }
                }
             } else {
                 if (p_n_1 == 0) {
                     if (p_n_sum == 0) {
                         printf("negative %s + %d = negative %s\n", words[count_1], count_2, words[count_sum]);
                     } else {
                         printf("negative %s + %d = %s\n", words[count_1], count_2, words[count_sum]);
                     }
                } else {
                   if (p_n_sum == 0){
                            printf("%s + %d = negative %s\n", words[count_1], count_2, words[count_sum]);
                        } else {
                            printf("%s + %d = %s\n", words[count_1], count_2, words[count_sum]);
                        }
                }
             }
        } else {
            if (p_n_2 == 0) {
                 if (p_n_sum == 0) {
                    printf("%d + negative %s = negative %s\n", count_1, words[count_2], words[count_sum]);
                } else {
                    printf("%d + negative %s = %s\n", count_1, words[count_2], words[count_sum]);
                }
            } else if (p_n_sum == 0) {
                 printf("%d + %s = negative %s\n", count_1, words[count_2], words[count_sum]);
            } else {
                 printf("%d + %s = %s\n", count_1, words[count_2], words[count_sum]);
            }
        }
     } else {
        if (count_1 >= -10 && count_1 <= 10) {
             if (count_2 >= -10 && count_2 <= 10) {
                 if (p_n_1 == 0) {
                     if (p_n_2 == 0) {
                        printf("negative %s + negative %s = %d\n", words[count_1], words[count_2], count_sum);
                    } else {
                         printf("negative %s + %s = %d\n", words[count_1], words[count_2], count_sum);
                     }
                } else {
                    if (p_n_2 == 0) {
                        printf("%s + negative %s = %d\n", words[count_1], words[count_2], count_sum);
                    }else {
                        printf("%s + %s = %d\n", words[count_1], words[count_2], count_sum);
                    }
                }
             } else {
                 if (p_n_1 == 0) {
                    printf("negative %s + %d = %d\n", words[count_1], count_2, count_sum);
                } else {
                    printf("%s + %d = %d\n", words[count_1], count_2, count_sum);
                }
            }
        } else {
            if (count_2 >= -10 && count_2 <= 10) {
                if (p_n_2 == 0) {
                    printf("%d + negative %s = %d\n", count_1, words[count_2], count_sum);
                } else {
                    printf("%d + %s = %d\n", count_1, words[count_2], count_sum);
                 }
            } else {
                 printf("%d + %d = %d\n", count_1, count_2, count_sum);
            }
        }
    }*/