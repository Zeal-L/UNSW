# 404: Ferrari++

Implement the following class specification in `src/ferrari.h` and/or `src/ferrari.cpp`.

| Method | Description |
|------|------|
|`ferrari(const std::string &owner, int modelno)`| This constructor should initialise the object state to keep track of the owner name and model number. Speed is initially 0. |
|`ferrari()`| This constructor should default-initialise the object's state so that its owner name is "unknown" and its model number is `6771`. Speed is initially 0.|
|`std::pair<std::string, int> get_details()`.| Returns this Ferrari's owner and model number.|
|`void drive(int spd)`.| Start driving at speed `spd`. If no speed is given, it should default to `88`.|
|`std::string vroom()`.| Returns a string depending on how fast this Ferrari is currently moving. If the speed is strictly less than 20, it should return the empty string. If `20 <= speed < 80`, it should return "vroom!!". Otherwise, it should return "VROOOOOOOOM!!!".|

**Note**: You need to ensure your code is const-correct. Which methods should be const-qualified has intentionally been left out.

When implementing this class, you should ensure you are using modern C++ best practices, such as member initialiser lists, delegating constructors, etc. You should check with your tutor to make sure that your style aligns with modern practices.

In `src/ferrari.test.cpp`, you will also need to write at least **five** tests to make sure your code is correct.

## Submission

This lab is due on Sunday 12th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.