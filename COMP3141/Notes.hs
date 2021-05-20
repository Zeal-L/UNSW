module Notes
    ( hypotenuse,
      identifyCamel,
      double,
      dividesEvenly,
      factorial,
      length1,
      length2,
      increasing,
      decreasing,
      isInorDe
    ) where

hypotenuse :: Floating a => a -> a -> a
hypotenuse a b = sqrt (a ^ (2 :: Int) + b ^ (2 :: Int))

identifyCamel :: (Eq a, Num a) => a -> [Char]
identifyCamel humps = if humps == 1
                      then "dromedary"
                      else "Bactrian"

double :: Num a => a -> a
double x = 2 * x

dividesEvenly :: Int -> Int -> Bool
dividesEvenly x y = (y `div` x) * x == y

factorial :: Integral a => a -> a
factorial 0 = 1
factorial n = n * factorial (n - 1)

length1 :: Num a => [a] -> a
length1 xs = sum [1 | _ <- xs]

length2 :: Num a => [a] -> a
length2 [] = 0
length2 (_:xs) = 1 + length2 xs

increasing :: Ord a => [a] -> Bool
increasing (x:y:ys) = x <= y && increasing (y:ys)
increasing _ = True

decreasing :: Ord a => [a] -> Bool
decreasing (x:y:ys) = x >= y && decreasing (y:ys)
decreasing _ = True

isInorDe :: (Ord a, Show a) => [a] -> IO ()
isInorDe x | increasing x = putStrLn (show x ++ " is in increasing order")                    
           | decreasing x = putStrLn (show x ++ " is in decreasing order")
           | otherwise    = putStrLn "no order"

data Compass = North | East | South | West
    deriving (Eq, Ord, Enum, Show)

