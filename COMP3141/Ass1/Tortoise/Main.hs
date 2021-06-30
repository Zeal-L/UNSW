module Main where

import Tortoise
import TortoiseGraphics
import TortoiseCombinators

square :: Distance -> Instructions
square s = Move s 
         $ Turn 90 
         $ Move s 
         $ Turn 90 
         $ Move s 
         $ Turn 90
         $ Move s 
         $ Turn 90 
         $ Stop


-- polygon drawing given a number of sides (s) and a side length (n)
-- N.B. The given number of sides best divide cleanly into 360.
polygon :: Int -> Integer -> Instructions
polygon s n = loop s (Move n $ Turn a $ Stop)
  where a = round (360 / fromIntegral s)

circle :: Instructions
circle = polygon 36 10

squareograph :: Instructions
squareograph = loop 36 (Turn 10 $ square 100)

circlograph :: Instructions
circlograph =  loop 360 (Turn 10 circle)

flower :: Instructions -> Instructions
flower top = SetColour brown 
           $ SetStyle (Solid 10) 
           $ Move 300 
           $ SetStyle (Solid 1) 
           $ SetColour yellow top

flowers :: Instructions -> Instructions
flowers top = Turn 45 flowers4 
  where
    flowers2 = flower top
     `andThen` invisibly (Turn 135 (Move 424 (Turn (-45) Stop)))
     `andThen` retrace (flower top)
    
    flowers4 = flowers2 `andThen` (Turn 90 flowers2)

flowers' :: Instructions -> Instructions
flowers' top = overlay [ Turn 45 f, Turn 135 f, Turn 225 f, Turn 315 f ]
  where f = flower top

flowerograph :: Instructions -> Instructions
flowerograph top = overlay $ map (\n -> Turn n (flower top)) [0,10..350]

circlographograph :: Instructions
circlographograph = overlay 
   $ map (\n -> SetColour (white { redC = fromIntegral n 
                                 , greenC = (360 - fromIntegral n)
                                 , blueC = (120 + fromIntegral n) 
                                 }) 
              $ Turn n (PenUp (Move 200 (PenDown circlograph))))
         [0,30..360]


ex1 = square 100
ex2 = squareograph
ex3 = circlograph
ex4 = flower squareograph
ex5 = flowers circlograph
ex6 = flowerograph squareograph
ex7 = circlographograph

main = do
  writePng "tortoise.png" (drawPicture $ tortoisePic ex1)
