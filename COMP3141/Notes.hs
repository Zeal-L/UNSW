{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE UndecidableInstances #-}
-- For map'
import Data.Char
import Data.List
-- For prop_reverse
import Test.QuickCheck ((==>), Positive(..))
import Test.QuickCheck.Property (Property)
import Debug.Trace ()
import qualified Data.Maybe as Maybes
-- ! ---------------------------------------------------------------------------

hypotenuse :: Floating a => a -> a -> a
hypotenuse a b = sqrt (a ^ (2 :: Int) + b ^ (2 :: Int))

-- ! ---------------------------------------------------------------------------

identifyCamel :: (Eq a, Num a) => a -> [Char]
identifyCamel humps = if humps == 1
                      then "dromedary"
                      else "Bactrian"

-- ! ---------------------------------------------------------------------------

double :: Num a => a -> a
double x = 2 * x

-- ! ---------------------------------------------------------------------------

dividesEvenly :: Int -> Int -> Bool
dividesEvenly x y = (y `div` x) * x == y

-- ! ---------------------------------------------------------------------------

factorial :: Integral a => a -> a
factorial 0 = 1
factorial n = n * factorial (n - 1)

-- ! ---------------------------------------------------------------------------

length1 :: Num a => [a] -> a
length1 xs = sum [1 | _ <- xs]

-- ! ---------------------------------------------------------------------------

length2 :: Num a => [a] -> a
length2 [] = 0
length2 (_:xs) = 1 + length2 xs

-- ! ---------------------------------------------------------------------------

increasing :: Ord a => [a] -> Bool
increasing (x:y:ys) = x <= y && increasing (y:ys)
increasing _ = True

decreasing :: Ord a => [a] -> Bool
decreasing (x:y:ys) = x >= y && decreasing (y:ys)
decreasing _ = True

checkOrder :: (Ord a, Show a) => [a] -> IO ()
checkOrder x
    | empty || only_one = error "No order"
    | increasing x = putStrLn $ "The list " ++ show x ++ " is in increasing order."
    | decreasing x = putStrLn $ "The list " ++ show x ++ " is in decreasing order."
    | otherwise    = error "No order"
    where empty    = null x
          only_one = length x == 1

-- ! ---------------------------------------------------------------------------

maximum' :: Ord a => [a] -> a
maximum' [] = error "maximum of empty list"
maximum' [x] = x
maximum' (x:xs) = max x (maximum' xs)

-- ! ---------------------------------------------------------------------------

take' :: (Ord t, Num t) => t -> [a] -> [a]
take' n _
    | n <= 0 = []
take' _ [] = []
take' n (x:xs) = x : take' (n - 1) xs

-- ! ---------------------------------------------------------------------------

reverse' :: [a] -> [a]
reverse' [] = []
reverse' (x:xs) = reverse' xs ++ [x]

-- accumulator style
proReverse :: [a] -> [a]
proReverse xs = go xs []
  where go []      acc = acc
        go (x:xs') acc = go xs' (x:acc)

-- ! ---------------------------------------------------------------------------

zip' :: [a] -> [b] -> [(a,b)]
zip' _ [] = []
zip' [] _ = []
zip' (x:xs) (y:ys) = (x,y):zip' xs ys

-- ! ---------------------------------------------------------------------------

-- 快速排序 :: 数组 -> 排序后的数组
quicksort :: Ord a => [a] -> [a]
quicksort [] = []
quicksort (x:xs) =
    let smallerSorted = quicksort [a | a <- xs, a <= x]
        biggerSorted = quicksort [a | a <- xs, a > x]
    in smallerSorted ++ [x] ++ biggerSorted

-- qsort :: Ord a => [a] -> [a]
-- qsort [] = []
-- qsort (x:xs) = qsort smaller ++ [x] ++ qsort larger
--     where
--     smaller = filter (\ a-> a <= x) xs
--     larger = filter (\ b-> b > x) xs

-- ! ---------------------------------------------------------------------------

-- 归并排序 :: 数组 -> 排序后的数组
mergeSort :: (Eq a, Ord a) => [a] -> [a]
mergeSort [] = []
mergeSort [x] = [x]      -- 如果是 只有一个元素的数组, 就返回这个数组
mergeSort xs = merge (mergeSort $ fst subs) (mergeSort $ snd subs)      -- 把 (被归并排序过的 前半部分的数组) 和 (被归并排序过的 后半部分的数组) 进行排序合并
    where mid = length xs `div` 2     -- 中心的下标
          subs = splitAt mid xs       -- 把数组分割成两个接近等份(奇数数量情况)或等份(偶数数量情况)的数组

-- 排序并合并两个数组 :: 数组 -> 另一个数组 -> 合并后的数组
merge :: (Eq a, Ord a) => [a] -> [a] -> [a]
merge [] ys = ys    -- 如果有任意一个数组为空, 则返回非空的那个数组
merge xs [] = xs
merge (x:xs) (y:ys) = if x < y
                      then x : merge xs (y:ys)      -- 如果 第一个数组的首元素小于 第二个数组的首元素, 则 排序剩下的两个数组, 并将 第一个数组的首元素添加在排序后的数组之前
                      else y : merge (x:xs) ys            -- 这里跟上面差不多啦

-- ! ---------------------------------------------------------------------------

data Day = Mon | Tue | Wed | Thu | Fri | Sat | Sun
    deriving (Eq, Ord, Enum, Show)

data People = People {
    name :: String,
    age :: Int
} deriving (Show)

-- data Tree a = Leaf { value :: a }
--     | Node {
--         left :: Tree a,
--         value :: a,
--         right :: Tree a }
--     deriving (Show)

-- ! ---------------------------------------------------------------------------

-- E.g Use of Monad
printN :: Int -> String -> IO ()
printN 0 _ = return ()
printN n str = putStrLn str >> printN (n - 1) str

-- ! ---------------------------------------------------------------------------

空格分割 :: IO [String]
空格分割 = words <$> getLine

-- ! ---------------------------------------------------------------------------

roots :: (Float, Float, Float) -> (Float, Float)
roots (a,b,c) = (x1, x2) where
   x1 = e + sqrt d / (2 * a)
   x2 = e - sqrt d / (2 * a)
   d = b * b - 4 * a * c
   e = - b / (2 * a)

-- ! ---------------------------------------------------------------------------

map' :: (a -> b) -> [a] -> [b]
map' _ [] = []
map' func (x : xs) = func x : map' func xs

-- ! ---------------------------------------------------------------------------

-- Lambda表达式
-- define a one-use function without giving it a name.
-- whatever :: IO ()
-- whatever = do
--    putStrLn "The successor of 4 is:"
--    print ((\x -> x + 1) 4)

-- ! ---------------------------------------------------------------------------

-- Function composition
-- (not'.even) 16 == not' $ even (16) == not' (even 16)
not'  :: Bool -> String
not' x = if x
            then "This is an Even Number"
         else "This is an Odd number"

-- ! ---------------------------------------------------------------------------

{-| Triple a list

>>>triple "5"
WAS "111111"
NOW "555"

>>> triple "ab"
"ababab"

prop> \(l::[Int]) -> length (triple l) == 3 * length l
+++ OK, passed 100 tests.

-}

triple :: [a] -> [a]
triple l = l ++ l ++ l

-- ! ---------------------------------------------------------------------------

-- check property
{-
>>> import Test.QuickCheck
>>> quickCheck prop_reverse
+++ OK, passed 100 tests.

-}

prop_reverse :: Eq a => [a] -> [a] -> Bool
prop_reverse xs ys =
    reverse' (xs ++ ys) == reverse' ys ++ reverse' xs



{- Mersenne prime property
prop> prop_mersennePrime
*** Failed! Falsified (after 24 tests):
Positive {getPositive = 11}

-}
prop_mersennePrime :: Positive Int -> Test.QuickCheck.Property.Property
prop_mersennePrime (Positive n) = isPrime n ==> isPrime $ 2^n - 1

isPrime :: Int -> Bool
isPrime = null . primeFactors

-- List the prime factors of a number (not including itself)
primeFactors :: Int -> [Int]
primeFactors x
  = filter (isFactor x) $ takeWhile (smallFactor x) primes
  where
    isFactor :: Int -> Int -> Bool
    isFactor xx y = xx `mod` y == 0

    smallFactor :: Int -> Int -> Bool
    smallFactor xx y = y * y <= xx

-- List of all primes in order
primes :: [Int]
primes = 2 : filter isPrime [3..]

-- ! ---------------------------------------------------------------------------

{-  substitution cipher
prop> \ xs -> encipher (encipher xs) == xs
+++ OK, passed 100 tests.

prop> \ xs -> length xs == length (encipher xs)
+++ OK, passed 100 tests.

>>> import Test.QuickCheck
>>> import Data.Char
>>> quickCheck (\ xs -> encipher (map toUpper xs) == map toUpper (encipher xs))
+++ OK, passed 100 tests.


prop> \ a b -> encipher (a ++ b) == encipher a ++ encipher b
+++ OK, passed 100 tests.

prop> \ x -> (encipher $ map toUpper x) == (map toUpper $ encipher x)
+++ OK, passed 100 tests.

prop> \ x -> not (null x) ==> 26 - ord (head x) == ord (head (encipher x))
*** Failed! Falsified (after 1 test and 1 shrink):
"a"
-}

encipher :: String -> String
encipher =
  let
    table = table' 'A' 'Z' ++ table' 'a' 'z'
    table' a z = zip [a..z] (reverse [a..z])
  in
    map $ \x -> Maybes.fromMaybe x (lookup x table)

-- ! ---------------------------------------------------------------------------

toHex :: Int -> String
toHex 0 = ""
toHex n =
  let
    (d,r) = n `divMod` 16
  in
    toHex d ++ ["0123456789ABCDEF" !! r]

fromHex :: String -> Int
fromHex = fst . foldr eachChar (0,1)
  where
    eachChar c (sum', m) =
      case elemIndex (toUpper c) "0123456789ABCDEF" of
        Just i  -> (sum' + i * m, m * 16)
        Nothing -> (sum'        , m * 16)

-- ! ---------------------------------------------------------------------------

dedup :: (Eq a) => [a] -> [a]  -- == nub
dedup (x:y:xs) | x == y    = dedup (y:xs)
               | otherwise = x : dedup (y:xs)
dedup xs = xs

sorted :: (Ord a) => [a] -> Bool
sorted (x:y:xs) = x <= y && sorted (y:xs)
sorted _xs       = True

-- ! ---------------------------------------------------------------------------

data Balance = Balance Int Int deriving (Show, Eq)

instance Semigroup Balance where
  Balance c1 o1 <> Balance c2 o2
    |   o1 > c2 = Balance c1 (o1 - c2 + o2)
    | otherwise = Balance (c1 + c2 - o1) o2

instance Monoid Balance where mempty = Balance 0 0

parseBalance :: Char -> Balance
parseBalance '(' = Balance 0 1
parseBalance ')' = Balance 1 0
parseBalance _   = Balance 0 0

balance :: [Char] -> Bool
balance str = mconcat (map parseBalance str) == Balance 0 0
