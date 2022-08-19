## Lab 10 - Choice Exercise - The Crown's Gambit

For this exercise,  you need to refactor the code provided that mostly implements the following game "The Crown's Gambit". Please note that you need to use the Strategy pattern in your refactoring. In order to properly refactor your code, you need to first understand the rules of this interesting game, which are provided below. Considering the game is mostly already implemented, in **most** of the cases you simply need to copy/paste the code. However, this exercise will demonstrate how you can improve your design by using a very useful Strategy Pattern.

The only things that aren't currently implemented
- All possible moves that a checker can make, currently we only check for Up Left for red checkers and Down Right for white checkers
  - The possible moves we don't include are Up Right and Down Left, these are trivial to add (just copying + pasting the if statement block and changing the directions) so weren't included to keep the function shorter.  You can find them in Checker.java
- Mad checkers turning other friendly checkers mad when jumping over them
  - How you do this will depend on your design as a hint have a look at how a piece gets crowned in Checkerboard.java
  - You may want to refactor crowning as well as part of your design

Checkers is a classic game with some relatively simple rules.

<img src="imgs/checkers.png" height=300 />

It's a 2 player game, in our version the pieces are red and white to represent the two different players.  Red goes first.

Each player takes their turn by moving a single piece diagonally forwards (towards the opponent) to the next dark square.

If there is a piece diagonally adjacent to one of your checkers you can 'jump' over that piece to the empty square on the other side.  You can only jump over enemy pieces.
  - If there isn't an empty square (i.e. 2 of red's pieces are placed diagonally adjacent) then you can't jump over both of them at the same time, capturing the piece
  - However, you can perform multiple jumps in a single turn given that there is an empty space between each piece.

<img src="imgs/jumping.png" height=300 />

Note: That making a 'silver' move still ends your turn, the system will handle the multiple sequential jumps if you click on one of the purple squares that 'branches' off from it.

If a piece makes it all the way to the end it 'crowns' gaining a unique symbol and the ability to move in both directions (forwards and backwards).

A player loses once they no longer have any more checkers available.

There are is a single options that is configurable upon defining a new game, there is already a checkbox in the start game screen to represent this.

- `Quackering` if this is set then every piece in the back row for both players goes mad, mad pieces are signified by a special symbol (as shown below) and *can* jump over your own pieces.  If your own piece gets jumped it doesn't get captured and instead just goes mad.  Crowned pieces can go mad (and mad pieces can get crowned).

<img src="imgs/quackening.png" height=300 />

Your task is to refactor the code such that it uses the strategy pattern to implement both the rendering of the checkers (i.e. the drawing of the circles) as well as the logic for which positions are valid.

To reiterate the only things that aren't currently implemented
- All possible moves that a checker can make, currently we only check for Up Left for red checkers and Down Right for white checkers
  - The possible moves we don't include are Up Right and Down Left, these are trivial to add (just copying + pasting the if statement block and changing the directions) so weren't included to keep the function shorter.  You can find them in Checker.java
- Mad checkers turning other friendly checkers mad when jumping over them
  - How you do this will depend on your design as a hint have a look at how a piece gets crowned in Checkerboard.java
  - You may want to refactor crowning as well as part of your design

Hints:

- Look at the unused interface `CheckerStrategy`.
- A checker piece could have multiple strategies that it aggregates, or it could just have a single strategy.
  - If you are aggregating strategies; avoid designing your code so that you need to check if a position is *already* valid, your strategies should be disjoint.
- Try to remove as much duplication as you can, especially in validPositions.
- You don't have to write *ANY* JavaFX code here, you'll want to grab the code that renders the checkers and move it around but you won't have to change it.
- Don't worry about the recursion of multiple jumps, the CheckerController handles this by checking if any of the valid positions can be used to jump again.  Just focus on the jumps you can make from a given position.

Finally, think about whether or not in this specific case the code really benefited from the strategy pattern, could you have applied the state pattern?  Compare it to the cases of strategy + state from tute with your tutor.

One final hint if you are really struggling (behind a spoiler just for those who want to push themselves):

<details>
<summary> A more substantial hint </summary>

There is nothing stopping you from having a strategy 'hold' / 'wrap' around another strategy. i.e.

```java
public class A implements Strategy {
  private Strategy inner;

  public A(Strategy inner) {
    this.inner = inner;
  }

  @Override
  public int foo() {
    return inner.foo() * 2;
  }
}
```

This way you could add / change how the inner function checks something, or just mutate it's result, or something inbetween.

</details>
