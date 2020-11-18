// Zeal L (abc982210694@gmail.com)
// 2020-10-27 21:50:32
// Seventh week in COMP1511
// Zid:z5325156
//
// Decrypts text encrypted by Substitution Cipher



#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int decodeSubCipher(int character, char argv[]);

int main(int argc, char *argv[]) {
    
    if (strlen(argv[1]) != 26) {
        return 0;
    }
    int character = getchar();
    while (character != EOF) {
    
        putchar(decodeSubCipher(character, argv[1]));
        character = getchar();
    }

    return 0;
}

int decodeSubCipher(int character, char argv[]) {

    int found_index = -1;
    int i = 0;

    if (character >= 'a' && character <= 'z') {
        while (argv[i] != '\0') {
            if (argv[i] == character) {
                found_index = i;
            }
            i++;
        }
        return 'a' + found_index;
    }

    if (character >= 'A' && character <= 'Z') {
        character += 32;
        while (argv[i] != '\0') {
            if (argv[i] == character) {
                found_index = i;
            }
            i++;
        }
        return 'A' + found_index;
    }

    return character;
}
// https://en.wikipedia.org/wiki/Letter_frequency

// Di jd, vdl'ht xtqa dh O qn
// Vdl rdlwk O'ss wdkith htqromu omkd ok
// O fhdwqwsv xdm'k
// Styk kd nv dxm rtzoetj
// Wlk kiqk'j kit royythtmet om dlh dfomodmj

// Vdl'ht q ndlkiyls
// Kiqk qndlmkj ydh qmdkith xtta dm nv dxm
// Mdx O'n q mdzts nqrt htjdlhetyls
// O jkqhk q eiqom xoki nv kidluik

// Kqsa oj eitqf, nv rqhsomu
// Xitm vdl'ht yttsomu houik qk idnt
// O xqmmq nqat vdl ndzt xoki edmyortmet
// O xqmmq wt xoki vdl qsdmt

// 'a' 0.012987 4
// 'b' 0.000000 0
// 'c' 0.000000 0
// 'd' 0.107143 33
// 'e' 0.022727 7
// 'f' 0.009740 3
// 'g' 0.000000 0
// 'h' 0.051948 16
// 'i' 0.055195 17
// 'j' 0.025974 8
// 'k' 0.084416 26
// 'l' 0.048701 15
// 'm' 0.081169 25
// 'n' 0.038961 12
// 'o' 0.077922 24
// 'p' 0.000000 0
// 'q' 0.077922 24
// 'r' 0.022727 7
// 's' 0.035714 11
// 't' 0.100649 31
// 'u' 0.016234 5
// 'v' 0.035714 11
// 'w' 0.019481 6
// 'x' 0.038961 12
// 'y' 0.025974 8
// 'z' 0.009740 3

// qwertyuio?asnmdf?hjklzx?v?

// bcgp

// qwertyuiobasnmdfchjklzxgvp

// Oh so, you're weak or I am 
// You doubt I'll bother reading into it 
// I probably won't 
// Left to my own devices 
// But that's the difference in our opinions 

// You're a mouthful 
// That amounts for another week on my own 
// Now I'm a novel made resourceful 
// I start a chain with my thought 

// Talk is cheap, my darling 
// When you're feeling right at home 
// I wanna make you move with confidence 
// I wanna be with you alone

