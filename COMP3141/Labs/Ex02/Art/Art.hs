module Art where

import ShapeGraphics
import Codec.Picture
import System.Random
import System.IO.Unsafe

centre :: Point
centre = Point 200 200

sharingan :: Picture
sharingan = [edge] ++ part1 ++ part2 ++ [miniCircle]
  where
    edge :: PictureObject
    edge = Circle centre 150 black Solid SolidFill

    miniCircle :: PictureObject
    miniCircle = Circle centre 20 black Solid SolidFill

    part1 :: Picture
    part1 = map myEllipse [pi/2, pi/6, -pi/6]
      where
        myEllipse :: Float -> PictureObject
        myEllipse angle
            = Ellipse centre 135 40 angle red Solid SolidFill

    part2 :: Picture
    part2 = map myEllipse [pi/2, pi/6, -pi/6]
        where
        myEllipse :: Float -> PictureObject
        myEllipse angle
            = Ellipse centre 135 40 angle black Solid NoFill


simpleCirclePic :: Float -> Picture
simpleCirclePic n =
    [Circle centre (x * (300/n)) (Colour 255 0 0 35) Solid SolidFill | x <- [1..n]]


art :: Picture
art = simpleCirclePic 17 ++ sharingan ++ tree'
  where
    tree' = tree 21 (Point 700 860) (Vector (-10) (-70)) (Colour 255 255 255 255) 0



tree :: Int -> Point -> Vector -> Colour -> Int -> Picture
tree depth treeBase treeDirection startColour change =
  let
    -- Scale of branches
    branchScale = 0.9
    -- Change in color for each iteration
    colourChange = Colour 3 3 3 255

    recursiveFractal :: Int -> Point -> Vector -> Colour -> Int -> [PictureObject]
    recursiveFractal x _ _ _ _ | x <= 0 = []
    recursiveFractal depth base direction colour change =
      [lineToPath (vectorLine base direction) colour Solid]
      ++ recursiveFractal (depth - ranDepth) topOfRoot leftDirection branchColour change
      ++ recursiveFractal (depth - ranDepth) topOfRoot rightDirection branchColour change
      where
        topOfRoot = movePoint base direction
        leftDirection = scaleVector branchScale $ rotateVector leftAngle direction
        rightDirection = scaleVector branchScale $ rotateVector rightAngle direction
        branchColour = subColour colour colourChange change
        ranDepth = randomInt int 0 3
        -- Angle of left branch (radians)
        leftAngle = randomInt float (-0.2) (-0.35)
        -- Angle of right branch (radians)
        rightAngle = randomInt float 0.2 0.35
        -- Change in color for each iteration

  in
    recursiveFractal depth treeBase treeDirection startColour (change + 5)

-- Produce a line by drawing a vector from a point
vectorLine :: Point -> Vector -> Line
vectorLine base vector = Line base $ movePoint base vector

-- Produce a picture object from a line
lineToPath :: Line -> Colour -> LineStyle -> PictureObject
lineToPath (Line start end) = Path [start, end]

-- Scale a vector by a given factor
scaleVector :: Float -> Vector -> Vector
scaleVector factor (Vector x y) = Vector (factor * x) (factor * y)

-- Rotate a vector by a given angle (in radians)
rotateVector :: Float -> Vector -> Vector
rotateVector angle (Vector x y) = Vector x' y'
  where
    x' = x * cos angle - y * sin angle
    y' = y * cos angle + x * sin angle

-- Offset a point using a vector for difference between points
movePoint :: Point -> Vector -> Point
movePoint (Point x y) (Vector dx dy)
  = Point (x + dx) (y + dy)

subColour :: Colour -> Colour -> Int ->Colour
subColour (Colour lr lg lb lo) (Colour rr rg rb ro) change =
  Colour (lightRed lr - rr - change) (mix lg - rg - change) (mix lb - rb - change) lo
    where lightRed x | x <= 0 = 20
                     | otherwise = x
          mix x | x <= 0 = 255
                | otherwise = x


writeToFile :: IO ()
writeToFile = writePng "art.png" (drawPicture 3 art)


randomInt fn a b = unsafePerformIO (fn <$> randomRIO (a, b))

int x = x :: Int
float x = x :: Float