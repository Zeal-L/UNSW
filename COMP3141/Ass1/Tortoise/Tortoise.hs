module Tortoise
  ( -- * Tortoise Graphics Language 
    -- ** Syntax
    Instructions (..)
    -- *** Line Styles
  , LineWidth
  , LineStyle(..)
    -- *** Measures
  , Angle
  , Distance
    -- *** Colours
  , Colour (..)
  , white, black, blue, red, green, yellow, magenta, orange, brown
    -- ** Semantics
  , tortoise
  , tortoisePic
  , finalState
  , start
    -- *** Pictures
  , Line (..)
  , Point
  , Picture
    -- *** State Transformers
  , TortoiseState (..)
  , comp
  , nop
  ) where

import Data.List(sort)

-- | Line width in pixels
type LineWidth = Int

-- | A line style is either solid, dashed, or dotted, with a particular pixel
--   width.
data LineStyle
  = Solid LineWidth
  | Dashed LineWidth
  | Dotted LineWidth
  deriving (Show, Eq)

-- | Angles in Degrees
type Angle    = Integer
-- | Distances in Pixels
type Distance = Integer

-- | A 2d vector indicating a coordinate (x,y).
--   (0,0) refers to the middle of the screen, and y grows upwards.
type Point = (Integer, Integer)

-- | Rotating an angle. Revolves the angle to be within the range (-180,180]
rotate :: Angle -> Angle -> Angle
rotate r a = revolve (a + r)
   where
     revolve n | n >   180 = revolve (n - 360)
               | n <= -180 = revolve (n + 360)
               | otherwise = n
-- | Adding two 2D vectors
plusV :: Point -> Point -> Point
plusV (x,y) (x',y') = (x + x', y + y')

-- | Converting polar to cartesian coordinates
cartesian :: Angle -> Distance -> Point
cartesian t r = ( round (fromIntegral r * cos' t )
                , round (fromIntegral r * sin' t )
                )

-- | Alternative sine function that gives consistent results despite floating
--   point inaccuracy.
--   Means our trigonometric identities should apply.
--   Achieves this by always taking the mantissa of the floating point number
--   from the domain of 0-180 degrees.
sin' :: Integer -> Double
sin' t | t >= 180  = -sin' (t - 180)
       | t < 0     = -sin' (t + 180)
       | otherwise = sin ((fromIntegral t * pi :: Double) / 180.0)

-- | Alternative cosine function that gives consistent results despite floating
--   point inaccuracy.
--   Means our trigonometric identities should apply.
--   Defined simply in terms of the alternative sine function with an offset.
cos' :: Integer -> Double
cos' t = sin' (t + 90)

-- | A colour is an 32-bit RGBA value. Each component ranges from 0-255. 
data Colour = Colour { redC, greenC, blueC, alphaC :: Int }
            deriving (Show, Eq)

-- | A set of useful predefined colours
white,black,blue,red,green,yellow,magenta,orange,brown :: Colour
white      = Colour 255  255 255 255
black      = Colour   0    0   0 255
blue       = Colour   0    0 255 255
red        = Colour 255    0   0 255
green      = Colour  10  255  10 255
yellow     = Colour  255 255   0 255
magenta    = Colour 153    0 153 255
orange     = Colour 254  154  46 255
brown      = Colour 128  75   22 255

-- | A Line consists of a style, colour, starting point and ending point
data Line = Line LineStyle Colour Point Point deriving (Show)

-- A line A - B is equal to a line B - A, so we use a custom Eq instance.
instance Eq Line where
  Line s c p1 p2 == Line s' c' p1' p2'
    =  s == s'
    && c == c'
    && sort [p1,p2] == sort [p1',p2']

-- | As our tortoise moves, it will generate a list of lines drawn. This
--   is a Picture.
type Picture = [Line]

-- | The TortoiseState type contains all the information needed to produce a
--   Picture from a list of instructions.
data TortoiseState =
  TortoiseState { position :: Point
                , facing   :: Angle
                , style    :: LineStyle
                , colour   :: Colour
                , penDown  :: Bool
                } deriving (Show, Eq)

-- | Our tortoise starts facing east, at the origin, with the pen down, colour
--   set to white, and a single pixel solid line style.
start :: TortoiseState
start = TortoiseState
      { position = (0,0)
      , facing   = 0
      , style    = Solid 1
      , colour   = white
      , penDown  = True
      }

-- | Composing state transformers first runs the first transformer from the
--   given state, then runs the second transformer with the output
--   state of the first, concatenating their output pictures.
--
--   We use a more general type than necessary to exploit parametricity to
--   ensure the correctness of our implementation.
comp :: (a -> (Picture, b)) -> (b -> (Picture, c))
     -> (a -> (Picture, c))
comp f g a = let (p , b) = f a
                 (p', c) = g b
              in (p ++ p', c)

-- | The identity state transformer. Does nothing to the state and returns
--   the empty picture.
nop :: (a -> (Picture, a))
nop a = ([],a)

-- | The actual Tortoise Graphics Language.
data Instructions
  = Move Distance Instructions
    -- ^ Move distance in the current facing direction. Will draw a line
    --   if the pen is down.
  | Turn Angle Instructions
    -- ^ Rotate facing direction by Angle.
  | SetStyle LineStyle Instructions
    -- ^ Change the current line style.
  | SetColour Colour Instructions
    -- ^ Change the current line colour.
  | PenDown Instructions
    -- ^ Put the pen down, so that subsequent Move instructions will draw.
  | PenUp Instructions
    -- ^ Lift the pen up , so that subsequent Move instructions will not draw.
  | Stop
    -- ^ Termination
  deriving (Show,Eq)

-- | The semantics of Instructions in terms of state transformers.
--   In other words, the actual function that converts instructions into
--    pictures.
tortoise :: Instructions -> TortoiseState -> (Picture, TortoiseState)
tortoise (PenDown i)      s = tortoise i (s { penDown = True })
tortoise (PenUp i)        s = tortoise i (s { penDown = False })
tortoise (Turn r i)       s = tortoise i (s { facing = rotate r (facing s) })
tortoise (SetStyle l i)   s = tortoise i (s { style = l })
tortoise (SetColour c i)  s = tortoise i (s { colour = c })
tortoise (Move m i)       s = let
      p' = position s `plusV` cartesian (facing s) m
      (pic,s') = tortoise i (s { position = p' })
   in if penDown s then (Line (style s) (colour s) (position s) p' : pic, s')
                   else (pic,s')
tortoise Stop s = ([],s)

-- | Utility function, just returns the picture given from a set of
--   instructions, starting from the initial state start.
tortoisePic :: Instructions -> Picture
tortoisePic i = fst (tortoise i start)

-- | Utility function, just returns the final state given from a set of
--   instructions, starting from the initial state start.
finalState :: Instructions -> TortoiseState
finalState i = snd (tortoise i start)
