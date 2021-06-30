{-# OPTIONS -fno-warn-orphans #-}
module TestSupport (MoveTurnOnly (..), NoPenControl (..)) where
import Control.Applicative ((<$>), (<*>))
import Tortoise
import Test.QuickCheck

-- Relative frequencies of:
-- Move, Turn, SetStyle, SetColour, PenDown, PenUp
-- respectively
type Frequencies = (Int,Int,Int,Int,Int,Int)

freqTable :: Frequencies -> [(Int,Gen (Instructions -> Instructions))]
freqTable (m,t,s,c,d,u)
   = [ (m, Move <$> choose (0,100))
     , (t, Turn <$> choose (-179,180))
     , (s, SetStyle <$> arbitrary)
     , (c, SetColour <$> elements colours)
     , (d, pure PenDown)
     , (u, pure PenUp)
     ]

colours :: [Colour]
colours = [white,black,blue,red,green,yellow,magenta,orange,brown]

arbitraryInstructions :: Frequencies -> Gen (Instructions) 
arbitraryInstructions freqs = sized $ \n -> case n of
     0 -> pure Stop
     _ -> frequency (freqTable freqs) <*> resize (n - 1) (arbitraryInstructions freqs)

instance Arbitrary LineStyle where
  arbitrary = oneof [ Solid  <$> choose (1,10)
                    , Dashed <$> choose (1,10)
                    , Dotted <$> choose (1,10)
                    ]

instance Arbitrary Instructions where
  shrink (Turn m (Turn n x)) = shrink (Turn (m + n) x)
  shrink (Move m x) = x : map (Move m) (shrink x)
  shrink (Turn m x) = x : map (Turn m) (shrink x)
  shrink (SetStyle m x) = x : map (SetStyle m) (shrink x)
  shrink (SetColour m x) = x : map (SetColour m) (shrink x)
  shrink (PenDown x) = x : map PenDown (shrink x)
  shrink (PenUp x) = x : map PenUp (shrink x)
  shrink (Stop) = []
  arbitrary = arbitraryInstructions (40,30,10,15,5,1)
                         
-- | Generates only Move and Turn constructors
newtype MoveTurnOnly = MoveTurnOnly Instructions  deriving (Show, Eq)
instance Arbitrary MoveTurnOnly where 
  arbitrary = MoveTurnOnly <$> arbitraryInstructions (40,30,0,0,0,0)
  shrink (MoveTurnOnly x) = MoveTurnOnly <$> shrink x

-- | Generates all constructors except for PenUp and PenDown
newtype NoPenControl = NoPenControl Instructions  deriving (Show, Eq)
instance Arbitrary NoPenControl where 
  arbitrary = NoPenControl <$> arbitraryInstructions (40,30,10,15,0,0)
  shrink (NoPenControl x) = NoPenControl <$> shrink x



