module Ex01 where

-- needed to display the picture in the playground
import Codec.Picture

-- our line graphics programming interface
import ShapeGraphics

-- Part 1
-- picture of a house
housePic :: Picture
housePic = [door, house]

chimneyHouse :: Picture
chimneyHouse = [door, chimneyH, window]

-- ! ---------------------------------------------------------------------------

house :: PictureObject
house = Path (cosToPoint houseCOs) green Solid

door :: PictureObject
door  = Path (cosToPoint doorCOs) red Solid

window :: PictureObject
window = Path (cosToPoint windowCOs) cyan Solid

chimneyH :: PictureObject
chimneyH = Path (cosToPoint chimneyHouseCOs) green Solid

cyan :: Colour
cyan = Colour 96 192 255 255

-- ! ---------------------------------------------------------------------------

cosToPoint :: [(Float, Float)] -> [Point]
cosToPoint = map $ uncurry Point

-- these are the coordinates - convert them to a list of Point
houseCOs :: [(Float, Float)]
houseCOs = [(300, 750), (300, 450), (270, 450), (500, 200),
          (730, 450), (700, 450), (700, 750)]

doorCOs :: [(Float, Float)]
doorCOs = [(550, 750), (550, 550), (650, 550), (650, 750)]

chimneyCOs :: [(Float, Float)]
chimneyCOs = [(615, 325), (615, 250), (650, 250), (650, 363)]

windowCOs :: [(Float, Float)]
windowCOs = [(350, 650), (350, 550), (450, 550), (450, 650), (350, 650)]

chimneyHouseCOs :: [(Float, Float)]
chimneyHouseCOs = houseStart ++ chimneyCOs ++ houseEnd
  where
    (houseStart, houseEnd) = splitAt 4 houseCOs

showPart1 :: IO ()
showPart1 = writeToFile chimneyHouse


-- Part 2
movePoint :: Point -> Vector -> Point
movePoint (Point x y) (Vector xv yv)
  = Point (x + xv) (y + yv)

movePictureObject :: Vector -> PictureObject -> PictureObject
movePictureObject vec (Path points colour lineStyle)
  = Path (map (`movePoint` vec) points) colour lineStyle
movePictureObject vec (Circle center radius colour lineStyle fillStyle)
  = Circle (movePoint center vec) radius colour lineStyle fillStyle
movePictureObject vec (Ellipse center width height rotation colour lineStyle fillStyle)
  = Ellipse (movePoint center vec) width height rotation colour lineStyle fillStyle
movePictureObject vec (Polygon points colour lineStyle fillStyle)
  = Polygon (map (`movePoint` vec) points) colour lineStyle fillStyle

showPart2 :: IO ()
showPart2 =
  let myRed = red { opacityC = 180 }
      xy = Point 400 400
      circ = Circle xy 100 myRed Solid SolidFill
      v = Vector 100 100
      pic = [circ, movePictureObject v circ]
  in writeToFile pic

-- Part 3


-- generate the picture consisting of circles:
-- [Circle (Point 400 400) (400/n) col Solid SolidFill,
--  Circle (Point 400 400) 2 * (400/n) col Solid SolidFill,
--  ....
--  Circle (Point 400 400) n * (400/n) col Solid SolidFill]
simpleCirclePic :: Colour -> Float -> Picture
simpleCirclePic col n =
    [Circle (Point 400 400) (x * (400/n)) col Solid SolidFill | x <- [1..n]]

showPart3 :: IO ()
showPart3 = writePng "ex01.png" $ drawPicture 2 $ simpleCirclePic myRed 5
  where
    myRed :: Colour
    myRed = Colour 255 0 0 80

showPart3b :: IO ()
showPart3b = writePng "ex01.png" $ drawPicture 2 $ simpleCirclePic myRed 150
  where
    myRed :: Colour
    myRed = Colour 255 0 0 5

-- use 'writeToFile' to write a picture to file "ex01.png" to test your
-- program if you are not using Haskell for Mac
-- e.g., call
-- writeToFile [house, door]

writeToFile pic
  = writePng "ex01.png" (drawPicture 3 pic)
