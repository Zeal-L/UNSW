# 208: Mixing Paint

C++ builds upon many constructs found in C. For example:
- `std::function` (and more) over raw function pointers
- `enum class` over `enum`
- `std::optional` over "magic" invalid values such as `nullptr` for an absent `T*`

In this exercise we shall implement a paint-mixing algorithm to gain familiarity with these new constructs. Namely:
- Paints will be represented by an `enum class` called `paint`.
- `sizeof(<any paint>) == 1`.
- The paint colours should be:
    - red
    - green
    - blue
    - yellow
    - cyan
    - magenta
    - brown
- Instead of baking-in which mixing strategy to use, we shall encapsulate it with a `std::function`.
- If a combination of colours doesn't exist, we will denote its absence by a `std::optional`.

In `src/mixing_paint.h`, there is documentation for a function `mix` that accepts a mixing strategy and vector of paints and mixes them according to the given strategy.

There is also documentation for a default mixing strategy `wacky_colour` which you will also need to implement.

Complete these functions in `src/mixer.cpp` and write at least **two tests** for `mixer` and **two tests** for `wacky_colour` in `src/mixer.test.cpp`.

## Submission

This lab is due on Sunday 26th February @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.