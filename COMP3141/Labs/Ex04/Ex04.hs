{-# LANGUAGE FlexibleContexts #-}
module Ex04 where
import Text.Read (readMaybe)
import System.IO
import Data.Char
import System.Environment
import Control.Monad.State
import System.Random
import Test.QuickCheck

onlyAlphabetic :: FilePath -> FilePath -> IO ()
onlyAlphabetic i o = do
  string <- readFile i
  writeFile o $ onlyAlpha string
  where
    onlyAlpha :: String -> String
    onlyAlpha [] = []
    onlyAlpha (x:xs)
      | isAlpha x = x : onlyAlpha xs
      | otherwise = onlyAlpha xs

-- $ filter isAlpha string

-- stack build
-- stack exec Ex04 -- "input.txt" "output.txt"

fileProduct :: IO ()
fileProduct = do
  [i, o] <- getArgs
  content <- readFile i
  let linesOfFiles = lines content
  writeFile o $ show (product' linesOfFiles)
  where
    product' :: [String] -> Int
    product' [] = 1
    product' [x] = read x
    product' (x:xs) = read x * product' xs


fileProduct' :: IO ()
fileProduct' = do
  [i, o] <- getArgs
  input <- readFile i
  writeFile o $ show (product $ map read $ words input) ++ "\n"
  -- writeFile o $ show (foldr (*) 1 $ map read $ words input) ++ "\n"




data Player m = Player { guess :: m Int
                       , wrong :: Answer -> m ()
                       }
data Answer = Lower | Higher

guessingGame :: (Monad m) => Int -> Int -> Player m -> m Bool
guessingGame x n p = go n
  where
   go 0 = pure False
   go n = do
     x' <- guess p
     case compare x x' of
       LT -> wrong p Lower  >> go (n-1)
       GT -> wrong p Higher >> go (n-1)
       EQ -> pure True

human :: Player IO
human = Player { guess = guess, wrong = wrong }
  where
    guess = do
      putStrLn "Enter a number (1-100):"
      x <- getLine
      case readMaybe x of
        Nothing -> guess
        Just i  -> pure i

    wrong Lower  = putStrLn "Lower!"
    wrong Higher = putStrLn "Higher!"

play :: IO ()
play = do
  x <- randomRIO (1,100)
  b <- guessingGame x 5 human
  putStrLn (if b then "You got it!" else "You ran out of guesses!")


midpoint :: Int -> Int -> Int
midpoint lo hi | lo <= hi  = lo + div (hi - lo) 2
               | otherwise = midpoint hi lo

ai :: Player (State (Int,Int))
ai = Player { guess = guess', wrong = wrong' }
  where
    guess' = get >>= return . (uncurry midpoint)

    wrong' Lower  = do
      guessed <- guess'
      (lo, _) <- get
      put (lo, guessed - 1)

    wrong' Higher = do
      guessed <- guess'
      (_, hi) <- get
      put (guessed + 1 , hi)




prop_basic (Positive n) = forAll (choose (1,n)) $ \x -> evalState (guessingGame x n ai) (1,n)

prop_optimality (Positive n) = forAll (choose (1,n)) $ \x -> evalState (guessingGame x (bound n) ai) (1,n)
  where bound n = ceiling (logBase 2 (fromIntegral n)) + 1


