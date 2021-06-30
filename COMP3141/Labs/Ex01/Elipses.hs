module Ellipses where

-- needed to display the picture in the playground
import Codec.Picture

-- our line graphics programming interface
import ShapeGraphics

simpleEllipsePic :: Float -> Picture
simpleEllipsePic n = map greenEllipse [0, pi/n .. (n-1)*pi/n]
  where
    greenEllipse :: Float -> PictureObject
    greenEllipse angle
        = Ellipse centre 250 70 angle (colourFor angle) Solid SolidFill

    colourFor :: Float -> Colour
    colourFor angle 
        = let x = round (255 * angle / pi)
           in Colour (255 - x) 255 x 60

    centre :: Point
    centre = Point 400 400

    
writeToFile pic
  = writePng "output.png" 
         (drawPicture 3 pic)