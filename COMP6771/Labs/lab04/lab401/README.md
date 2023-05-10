# 401: Namespaces & Scopes

Consider the following program:

```cpp
#include <iostream>

namespace {
    auto i = 42;
}

namespace comp6771 {
    auto i = 6771;

    auto foo(int) -> void {
        std::cout << "comp6771::foo(int)" << std::endl;
    }
}

namespace comp6772 {
    auto foo(int) -> void {
        std::cout << "comp6772::foo(int)" << std::endl;
    }

    auto foo(char) -> void {
        std::cout << "comp6772::foo(char)" << std::endl;
    }
}

namespace comp6773 {
    struct uchar {
        unsigned char c;
    };

    auto bar(uchar) -> void {
        std::cout << "comp6773::bar(comp6773::uchar)" << std::endl;
    }
}

int main() {
    std::cout << i << std::endl;        
    {
        int i = 0;                      
        std::cout << i << std::endl;    

        using ::i;                      
        std::cout << i << std::endl;    
    }

    comp6771::foo(i);                   
    comp6772::foo(i);                   

    using namespace comp6771;           
    using namespace comp6772;           

    foo(i);                                                                     

    foo('c');                         

    auto uc = comp6773::uchar{'c'};     
    bar(uc);                            
}
```

Some of the lines of this program are ill-formed according to C++'s rules about namespaces and scopes.

Figure out which lines of this program are ill-formed and write down the line numbers in `src/answers.txt`. You should write the line numbers in ascending order, one per line.

**Hint**: you should pretend you are like a compiler and are only look at this source file as it is. Don't try and remove any lines as that could make subsequent lines become well-formed.


## Submission

This lab is due on Sunday 12th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
