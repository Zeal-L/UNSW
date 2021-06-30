module Ex02 where
import Test.QuickCheck ()
import Data.List ()
-- implement the following functions, which meet some (but not all!) of the
-- properties of a correct sorting function

-- prop1 & 4, but not prop2 & 3 & 5
{-
prop> sortProp1 dodgySort1
+++ OK, passed 100 tests.
prop> sortProp2 dodgySort1
*** Failed! Falsified (after 5 tests and 5 shrinks):
[0,1]
prop> sortProp3 dodgySort1
*** Failed! Falsified (after 7 tests and 5 shrinks):
[0,-1]
prop> sortProp4 dodgySort1
+++ OK, passed 100 tests.
prop> sortProp5 dodgySort1
*** Failed! Falsified (after 4 tests and 4 shrinks):
[1,0]

-}
dodgySort1 :: [Int] -> [Int]
dodgySort1 xs = xs


-- prop2 & 3 & 4, but not prop1 & 5
{-
prop> sortProp1 dodgySort2
*** Failed! Falsified (after 1 test):
[]
prop> sortProp2 dodgySort2
+++ OK, passed 100 tests.
prop> sortProp3 dodgySort2
+++ OK, passed 100 tests.
prop> sortProp4 dodgySort2
+++ OK, passed 100 tests.
prop> sortProp5 dodgySort2
*** Failed! Falsified (after 1 test):
[]

-}
dodgySort2 :: [Int] -> [Int]
dodgySort2 x = sort x ++ [maxBound :: Int]
  where
    sort [] = []
    sort (xx:xs) =
      let smallerSorted = sort [a | a <- xs, a <= xx]
          biggerSorted = sort [a | a <- xs, a > xx]
      in smallerSorted ++ [xx] ++ biggerSorted


-- prop1 & 2 & 3, but not prop4 & 5
{-
prop> sortProp1 dodgySort3
+++ OK, passed 100 tests.
prop> sortProp2 dodgySort3
+++ OK, passed 100 tests.
prop> sortProp3 dodgySort3
+++ OK, passed 100 tests.
prop> sortProp4 dodgySort3
*** Failed! Falsified (after 1 test):
0
[]
[]
prop> sortProp5 dodgySort3
*** Failed! Falsified (after 2 tests):
[0]

-}
dodgySort3 :: [Int] -> [Int]
dodgySort3 = recur
  where recur [] = []
        recur (_:xs) = 1 : recur xs


-- prop1 & 2 & 3 & 4, but not prop5
{-
prop> sortProp1 dodgySort4
+++ OK, passed 100 tests.
prop> sortProp2 dodgySort4
+++ OK, passed 100 tests.
prop> sortProp3 dodgySort4
+++ OK, passed 100 tests.
prop> sortProp4 dodgySort4
+++ OK, passed 100 tests.
prop> sortProp5 dodgySort4
*** Failed! Falsified (after 5 tests and 2 shrinks):
[4,4]

-}
dodgySort4 :: [Int] -> [Int]
dodgySort4 [] = []
dodgySort4 [x] = [x]
dodgySort4 y = quicksort $ removeDups y
  where
    quicksort :: Ord a => [a] -> [a]
    quicksort [] = []
    quicksort (x:xs) =
      let smallerSorted = quicksort [a | a <- xs, a <= x]
          biggerSorted = quicksort [a | a <- xs, a > x]
      in smallerSorted ++ [x] ++ biggerSorted

    removeDups :: [Int] -> [Int]
    removeDups xs = remove $ quicksort xs
      where
        remove []  = []
        remove [z] = [z]
        remove (x1:x2:xx)
          | x1 == x2  = 1:x1:xx
          | otherwise = x1 : remove (x2:xx)


-- Properties of sorting function
-- 1:长度是否还一致
sortProp1 :: ([Int] -> [Int]) -> [Int] -> Bool
sortProp1 sortFn xs = length xs == length (sortFn xs)

-- 2:是否正确排序颠倒列表
sortProp2 :: ([Int] -> [Int]) -> [Int] -> Bool
sortProp2 sortFn xs = sortFn xs == sortFn (reverse xs)

-- 3:是否正确排序
sortProp3 :: ([Int] -> [Int]) -> [Int] -> Bool
sortProp3 sortFn xs = isSorted (sortFn xs)
  where
    isSorted (x1 : x2 : xs) = (x1 <= x2) && isSorted (x2 : xs)
    isSorted _ = True

-- 4:是否删除了头元素
sortProp4 :: ([Int] -> [Int]) -> Int -> [Int] -> [Int] -> Bool
sortProp4 sortFn x xs ys = x `elem` sortFn (xs ++ [x] ++ ys)

-- 5:是否和插入排序一样具有稳定性
sortProp5 :: ([Int] -> [Int]) -> [Int] -> Bool
sortProp5 sortFn xs
  = sortFn xs == insertionSort xs

insertionSort :: [Int] -> [Int]
insertionSort xs = foldr insertSorted [] xs
  where
    insertSorted x [] = [x]
    insertSorted x (y : ys)
      | x <= y = x : y : ys
      | otherwise = y : insertSorted x ys

