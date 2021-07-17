{-# LANGUAGE GADTs, DataKinds, KindSignatures, TupleSections, PolyKinds, TypeOperators, TypeFamilies, PartialTypeSignatures #-}
module Hare where
import Control.Monad
import Control.Applicative
import HareMonad

data RE :: * -> * where
  Empty  :: RE ()
  Fail   :: RE a
  Char   :: [Char] -> RE Char
  Seq    :: RE a -> RE b -> RE (a, b)
  Choose :: RE a -> RE a -> RE a
  Star   :: RE a -> RE [a]
  Action :: (a -> b) -> RE a -> RE b

match :: (Alternative f, Monad f) => RE a -> Hare f a
match Empty = pure ()
match Fail = failure
match (Char xs)    = readCharacter >>= \x -> guard (x `elem` xs) >> pure x
match (Seq a b)    = pair <$> match a <*> match b
                      where
                        pair x y = (x, y)
match (Choose a b) = match a <|> match b
match (Star a)     = (:) <$> match a <*> match (Star a) <|> pure []
match (Action f a) = f <$> match a

matchAnywhere :: (Alternative f, Monad f) => RE a -> Hare f a
matchAnywhere re = match re <|> (readCharacter >> matchAnywhere re)

(=~) :: (Alternative f, Monad f) => String -> RE a -> f a
(=~) = flip (hare . matchAnywhere)

-- "ab01cd20" =~ Action f (atoz `Seq` atoz) :: [String]


infixr `cons`
-- "10100" =~ cons (Char ['1']) (Star (Char ['0'])) :: [String]
-- "10100" =~ cons (Char ['1']) (Action (const []) Empty) :: [String]
cons :: RE a -> RE [a] -> RE [a]
cons x xs = Action (uncurry (:)) (Seq x xs)

-- "My favourite subject is COMP3141" =~ string "COMP3141" :: Maybe String
-- "My favourite subject is MATH1141" =~ string "COMP3141" :: Maybe String
string :: String -> RE String
string = foldr (\x -> cons (Char [x])) (Action (const []) Empty)

-- "foo" =~ rpt 0 (Char ['a']) :: Maybe [Char]
rpt :: Int -> RE a -> RE [a]
rpt 0 _  = Action (const []) Empty
rpt n re = cons re (rpt (n-1) re)

-- "1234" =~ rptRange (3,3) (Char ['0'..'9']) :: [String]
rptRange :: (Int, Int) -> RE a -> RE [a]
rptRange (x,y) re = choose $ map (`rpt` re) [y, y-1..x]

-- "foo" =~ option (Char ['a']) :: [Maybe Char]
option :: RE a -> RE (Maybe a)
option re = Choose (Action Just re) (Action (\()-> Nothing) Empty)

-- "10100" =~ plus (Char ['0']) :: [String]
plus :: RE a -> RE [a]
plus re = cons re (Star re)

-- "COMP3141, MATH1081, PHYS1121, COMP3121" =~ choose [string "COMP", string "MATH", string "PHYS"] :: [String]
-- "abc" =~ choose [] :: Maybe String
choose :: [RE a] -> RE a
choose = foldr Choose Fail
