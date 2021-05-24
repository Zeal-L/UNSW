module Notes (           
          hypotenuse, identifyCamel,
          double,     dividesEvenly,
          factorial,  length1,
          length2,    increasing,
          decreasing, checkOrder,
          maximum',   take',
          reverse',   zip',
          quicksort,  mergeSort,
          printN,     空格分割,
          roots,      map',
          not'
    ) where

import Data.Char  -- For map'

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

-- ! ---------------------------------------------------------------------------

-- 归并排序 :: 数组 -> 排序后的数组
mergeSort :: (Eq a, Ord a) => [a] -> [a]
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

data Tree a = Leaf { value :: a }
    | Node { 
        left :: Tree a,
        value :: a, 
        right :: Tree a }
    deriving (Show)

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
map' func (x : abc) = func x : map func abc  

-- ! ---------------------------------------------------------------------------

-- Lambda表达式
-- whatever :: IO ()
-- whatever = do 
--    putStrLn "The successor of 4 is:"  
--    print ((\x -> x + 1) 4)

-- ! ---------------------------------------------------------------------------

-- Function composition
-- (not'.even)(16) == not' $ even (16)
not'  :: Bool -> String 
not' x = if x 
            then "This is an Even Number" 
         else "This is an Odd number" 



-- ! ---------------------------------------------------------------------------
