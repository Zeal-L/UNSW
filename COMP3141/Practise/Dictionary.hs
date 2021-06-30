-- Zeal L (abc982210694@gmail.com)
-- 2021-06-23 16:39:59
-- Zid: z5325156
--
-- Dictionary (data invariants) 数据不变性

module Dictionary
  ( Word
  , Definition
  , Dict
  , emptyDict
  , insertWord
  , lookup
  ) where

import Prelude hiding (Word, lookup)
import Test.QuickCheck ( (==>), Arbitrary(arbitrary), OrderedList(Ordered), Property)

type Word = String
type Definition = String

newtype Dict = D [DictEntry]
             deriving (Show, Eq)

data DictEntry = Entry { word :: Word
          , defn :: Definition
          } deriving (Eq, Show)

instance Ord DictEntry where
    Entry w1 _d1 <= Entry w2 _d2 = w1 <= w2

instance Arbitrary DictEntry where
    arbitrary = Entry <$> arbitrary <*> arbitrary

instance Arbitrary Dict where
    arbitrary = do
    Ordered ds <- arbitrary
    pure (D ds)

emptyDict :: Dict
emptyDict = D []

insertWord :: Word -> Definition -> Dict -> Dict
insertWord w def (D defs) = D (insertEntry (Entry w def) defs)
  where
    insertEntry wd (x:xs) = case compare (word wd) (word x)
                              of GT -> x : insertEntry wd xs
                                 EQ -> wd : xs
                                 LT -> wd : x : xs
    insertEntry wd [] = [wd]

lookup :: Word -> Dict -> Maybe Definition
lookup w (D es) = search w es
  where
    search _wd [] = Nothing
    search wd (e:ess) = case compare wd (word e) of
       LT -> Nothing
       EQ -> Just (defn e)
       GT -> search w ess

-- ! ---------------------------------------------------------------------------
-- Property quickCheck

_wellformed :: Dict -> Bool
_wellformed (D es) = _sorted es

_sorted :: (Ord a) => [a] -> Bool
_sorted []  = True
_sorted [_x] = True
_sorted (x:y:xs) = x <= y && _sorted (y:xs)

{- prop> _propInsertWf
+++ OK, passed 100 tests.

-}
_propInsertWf :: Dict -> Word -> Definition -> Property
_propInsertWf dict w d = _wellformed dict ==> _wellformed (insertWord w d dict)
{- prop> _propArbitraryWf
+++ OK, passed 100 tests.

-}
_propArbitraryWf :: Dict -> Bool
_propArbitraryWf = _wellformed
