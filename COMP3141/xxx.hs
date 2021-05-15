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

increasing :: (Ord a) => [a] -> Bool
increasing (x:y:ys) = x <= y && increasing (y:ys)
increasing _ = True

decreasing :: (Ord a) => [a] -> Bool
decreasing (x:y:ys) = x >= y && decreasing (y:ys)
decreasing _ = True

isInorDe :: (Ord a) => [a] -> [Char]
isInorDe x | increasing x = "is in increasing order"
           | decreasing x = "is in decreasing order"
           | otherwise = "is not in increasing order nor in decreasing order"

