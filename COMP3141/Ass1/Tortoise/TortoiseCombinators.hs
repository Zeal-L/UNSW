module TortoiseCombinators
       ( andThen
       , loop
       , invisibly
       , retrace
       , overlay
       ) where

import Tortoise

-- See Tests.hs or the assignment spec for specifications for each
-- of these combinators.

-- ! ---------------------------------------------------------------------------

andThen :: Instructions -> Instructions -> Instructions
andThen (Move distance i1) i2      = Move distance      $ andThen i1 i2
andThen (Turn angle i1) i2         = Turn angle         $ andThen i1 i2
andThen (SetStyle lineStyle i1) i2 = SetStyle lineStyle $ andThen i1 i2
andThen (SetColour colour i1) i2   = SetColour colour   $ andThen i1 i2
andThen (PenDown i1) i2            = PenDown            $ andThen i1 i2
andThen (PenUp i1) i2              = PenUp              $ andThen i1 i2
andThen i Stop                     = i
andThen Stop i                     = i

-- ! ---------------------------------------------------------------------------

loop :: Int -> Instructions -> Instructions
loop n i | n <= 0 = Stop
         | otherwise =  andThen i $ loop (n - 1) i

-- ! ---------------------------------------------------------------------------

type PenState = Bool
invisibly :: Instructions -> Instructions
invisibly i = doInvis i True
  where
    doInvis :: Instructions -> PenState -> Instructions
    doInvis (Move distance i)      state = PenUp $ Move distance      $ doInvis i state
    doInvis (Turn angle i)         state = PenUp $ Turn angle         $ doInvis i state
    doInvis (SetStyle lineStyle i) state = PenUp $ SetStyle lineStyle $ doInvis i state
    doInvis (SetColour colour i)   state = PenUp $ SetColour colour   $ doInvis i state
    doInvis (PenDown i) _                = PenUp $ doInvis i True
    doInvis (PenUp i) _                  = doInvis i False
    doInvis Stop True                    = PenDown Stop
    doInvis Stop False                   = Stop

-- ! ---------------------------------------------------------------------------

data State =
  State { style'    :: LineStyle
        , colour'   :: Colour
        , penDown'  :: Bool
        } deriving (Show, Eq)

curr :: State
curr = State
  { style'   = Solid 1
  , colour'  = white
  , penDown' = True
  }

retrace :: Instructions -> Instructions
retrace i = doR i Stop curr
  where
    doR :: Instructions -> Instructions -> State -> Instructions
    doR (Move distance i1) i2         state                 = doR i1 (Move (-distance) i2)  state
    doR (Turn angle i1) i2            state                 = doR i1 (Turn (-angle) i2)     state
    doR (SetStyle newLineStyle i1) i2 s@(State style' _ _)  = doR i1 (SetStyle style' i2)   s { style'   = newLineStyle }
    doR (SetColour newColour i1) i2   s@(State _ colour' _) = doR i1 (SetColour colour' i2) s { colour'  = newColour }
    doR (PenUp   i1) i2               s@(State _ _ True)    = doR i1 (PenDown i2)           s { penDown' = False }
    doR (PenUp   i1) i2               s@(State _ _ False)   = doR i1 (PenUp   i2)           s { penDown' = False }
    doR (PenDown i1) i2               s@(State _ _ True)    = doR i1 (PenDown i2)           s { penDown' = True }
    doR (PenDown i1) i2               s@(State _ _ False)   = doR i1 (PenUp   i2)           s { penDown' = True }
    doR Stop i2 _                                           = i2

-- ! ---------------------------------------------------------------------------

overlay :: [Instructions] -> Instructions
overlay []  = Stop
overlay [i] = andThen i $ goBack i
overlay (i  : is) = andThen i $ andThen (goBack i) (overlay is)

goBack :: Instructions -> Instructions
goBack i = retrace $ invisibly i
