module Sharingan where

-- needed to display the picture in the playground
import Codec.Picture

-- our line graphics programming interface
import ShapeGraphics

sharinganPic1 :: Picture
sharinganPic1 = [background, edge] ++ part1 ++ part2 ++ [miniCircle]
  where
    miniCircle :: PictureObject
    miniCircle = Circle centre 40 black Solid SolidFill

    part1 :: Picture
    part1 = map myEllipse [pi/2, pi/6, -pi/6]
      where
        myEllipse :: Float -> PictureObject
        myEllipse angle
            = Ellipse centre 270 80 angle red Solid SolidFill

    part2 :: Picture
    part2 = map myEllipse [pi/2, pi/6, -pi/6]
        where
        myEllipse :: Float -> PictureObject
        myEllipse angle
            = Ellipse centre 270 80 angle black Solid NoFill


sharinganPic2 :: Picture
sharinganPic2 = [background, edge, mainCircle] ++ part1 ++ [miniCircle]
  where
    mainCircle :: PictureObject
    mainCircle = Circle centre 280 red Solid SolidFill

    miniCircle :: PictureObject
    miniCircle = Circle centre 35 black Solid SolidFill

    part1 :: Picture
    part1 = map myEllipse [pi/2, pi/6, -pi/6]
        where
        myEllipse :: Float -> PictureObject
        myEllipse angle
            = Ellipse centre 280 90 angle black Solid NoFill



edge :: PictureObject
edge = Circle centre 300 black Solid SolidFill

background :: PictureObject
background = Polygon (cosToPoint bgCOs) charcoalGrey Solid SolidFill
    where
    bgCOs :: [(Float, Float)]
    bgCOs = [(0, 0), (800, 0), (800, 800), (0, 800)]

    charcoalGrey :: Colour
    charcoalGrey = Colour 25 25 25 255

centre :: Point
centre = Point 400 400

cosToPoint :: [(Float, Float)] -> [Point]
cosToPoint = map (uncurry Point)

showIt1 = writePng "Sharingan.png" (drawPicture 5 sharinganPic1)
showIt2 = writePng "Sharingan1.png" (drawPicture 14 sharinganPic2)