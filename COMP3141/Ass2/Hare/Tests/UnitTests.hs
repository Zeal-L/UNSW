{-# LANGUAGE TupleSections #-}
module Tests.UnitTests where
import Data.List
import Test.Tasty.QuickCheck
import Hare 


test_empty_maybe = testProperty "empty (maybe)" $
   \s -> (s =~ Empty) == Just ()
test_empty_list = testProperty "empty (list)" $ 
   \s -> (s =~ Empty) == replicate (length s + 1) ()

test_fail_maybe = testProperty "fail (maybe)" $ 
   \s -> (s =~ Fail) == (Nothing  :: Maybe ())
test_fail_list = testProperty "fail (list)" $ 
   \s -> (s =~ Fail) == ([] :: [()])

test_char_filter = testProperty "char (list) is like filter" $
   \s xs -> (s =~ Char xs) == filter (`elem` xs) s

test_char_maybe = testProperty "char (maybe)" $ 
   \s c -> ((s =~ Char [c]) == Just c) == (c `elem` s)

test_seq_1 = testProperty "fail in seq 1" $
   \s c -> (s =~ (Fail `Seq` Char c)) == ([] :: [((), Char)]) 

test_seq_2 = testProperty "fail in seq 2" $
   \s c -> (s =~ (Char c `Seq` Fail)) == ([] :: [(Char, ())])

test_seq_3 = testProperty "empty in seq 1" $
   \s c -> (s =~ (Empty `Seq` Char c)) == map (() ,) (s =~ Char c)

test_seq_4 = testProperty "empty in seq 2" $
   \s c -> (s =~ (Char c `Seq` Empty)) == map (, ()) (s =~ Char c)

test_seq_5 = testProperty "two chars in seq" $
   \s c1 c2 -> case (s =~ (Char c1 `Seq` Char c2)) of 
                Nothing -> not $ any (`substring` s) [ [a,b] | a <- c1, b <- c2]
                Just (a,b) -> [a,b] `substring` s

test_ch_1 = testProperty "fail in choose 1" $ 
  \s c -> ((s =~ Char c) :: [Char]) == (s =~ (Char c `Choose` Fail))

test_ch_2 = testProperty "fail in choose 2" $ 
  \s c -> ((s =~ Char c) :: [Char]) == (s =~ (Fail `Choose` Char c))

test_ch_3 = testProperty "two chars in choose" $ 
  \s c1 c2 -> ((s =~ (Char c1 `Choose` Char c2)) :: Maybe Char) == (s =~ Char (c1 ++ c2))

test_ch_4 = testProperty "choose and seq 1" $
  \s c1 c2 c3 -> ((s =~ (Char c1 `Seq` (Char c2 `Choose` Char c3))) :: [(Char,Char)])
             ==  ((s =~ ((Char c1 `Seq` Char c2) `Choose` (Char c1 `Seq` Char c3))))

test_ch_5 = testProperty "choose and seq 2" $
  \s c1 c2 c3 -> ((s =~ ((Char c2 `Choose` Char c3) `Seq` Char c1)) :: [(Char,Char)])
             ==  ((s =~ ((Char c2 `Seq` Char c1) `Choose` (Char c3 `Seq` Char c1))))

test_star_1 = testProperty "star replicate" $
  \n c -> let s = replicate n c in sort (s =~ Star (Char [c])) == sort (concatMap inits (inits s))

test_star_2 = testProperty "star fail" $
   \s -> ((s =~ Star Fail) :: [[()]]) == replicate (length s + 1) []

test_star_3 = testProperty "star char" $
   \s c -> (all (== []) ((s =~ Star (Char c)) :: [String]))
        == not (any (`elem` c) s)

substring :: String -> String -> Bool
substring x y = any (x `isPrefixOf`) (tails y)