#include "sort3.h"

auto sort3(int &a, int &b, int &c) -> void {
    if (a > b) {
        int temp = a;
        a = b;
        b = temp;
    }
    if (b > c) {
        int temp = b;
        b = c;
        c = temp;
    }
    if (a > b) {
        int temp = a;
        a = b;
        b = temp;
    }

}

auto sort3(std::string &a, std::string &b, std::string &c) -> void {
    if (a > b) {
        std::string temp = a;
        a = b;
        b = temp;
    }
    if (b > c) {
        std::string temp = b;
        b = c;
        c = temp;
    }
    if (a > b) {
        std::string temp = a;
        a = b;
        b = temp;
    }

}