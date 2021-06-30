module Ex03 where

import Test.QuickCheck
import Data.List(sort, nub)

data BinaryTree = Branch Integer BinaryTree BinaryTree
                | Leaf
                deriving (Show, Ord, Eq)

isBST :: BinaryTree -> Bool
isBST Leaf = True
isBST (Branch v l r)
  = allTree (< v) l  &&
    allTree (>= v) r &&
    isBST l          &&
    isBST r
  where allTree :: (Integer -> Bool) -> BinaryTree -> Bool
        allTree f (Branch v l r) = f v && allTree f l && allTree f r
        allTree f (Leaf) = True

--Add an integer to a BinaryTree, preserving BST property.
insert :: Integer -> BinaryTree -> BinaryTree
insert i Leaf = Branch i Leaf Leaf
insert i (Branch v l r)
  | i < v     = Branch v (insert i l) r
  | otherwise = Branch v l (insert i r)

--Remove all instances of an integer in a binary tree, preserving BST property
deleteAll :: Integer -> BinaryTree -> BinaryTree
deleteAll i Leaf = Leaf
deleteAll i (Branch j Leaf r) | i == j = deleteAll i r
deleteAll i (Branch j l Leaf) | i == j = deleteAll i l
deleteAll i (Branch j l r) | i == j = let (x, l') = deleteRightmost l
                                       in Branch x l' (deleteAll i r)
                           | i <  j = Branch j (deleteAll i l) r
                           | i >  j = Branch j l (deleteAll i r)
  where deleteRightmost :: BinaryTree -> (Integer, BinaryTree)
        deleteRightmost (Branch i l Leaf) = (i, l)
        deleteRightmost (Branch i l r)    = let (x, r') = deleteRightmost r
                                             in (x, Branch i l r')

searchTrees :: Gen BinaryTree
searchTrees = sized searchTrees'
  where
   searchTrees' 0 = return Leaf
   searchTrees' n = do
      v <- (arbitrary :: Gen Integer)
      fmap (insert v) (searchTrees' $ n - 1)

----------------------
{-
prop> prop_mysteryProp_1
+++ OK, passed 100 tests.
prop> prop_mysteryProp_2
+++ OK, passed 100 tests.
-}
-- 可能是统计树里面有多少个指定int，
mysteryProp :: Integer -> BinaryTree -> Int
mysteryProp _ Leaf = 0
mysteryProp i (Branch v l r)
  | i == v = 1 + mysteryProp i r
  | i < v     = 0 + mysteryProp i l
  | otherwise = 0 + mysteryProp i r

-- 先插入这个int到树里再用mystery，结果要比直接用mystery要大
prop_mysteryProp_1 :: Integer -> Property
prop_mysteryProp_1 integer =
  forAll searchTrees $ \tree ->
    mysteryProp integer (insert integer tree) > mysteryProp integer tree

-- 先把树全部删光，再用mystery int
prop_mysteryProp_2 :: Integer -> Property
prop_mysteryProp_2 integer =
  forAll searchTrees $ \tree ->
    mysteryProp integer (deleteAll integer tree) == 0

----------------------
-- 把树转成顺序链表
mysterious :: BinaryTree -> [Integer]
mysterious Leaf = []
mysterious (Branch v l r) = mysterious l ++ [v] ++ mysterious r

{-
prop> prop_mysterious_1
+++ OK, passed 100 tests.
prop> prop_mysterious_2
+++ OK, passed 100 tests.
-}

isSorted :: [Integer] -> Bool
isSorted (x:y:rest) = x <= y && isSorted (y:rest)
isSorted _ = True

-- 对比同一元素的数量是否在树中和转化的顺序链表中一致
prop_mysterious_1 :: Integer -> Property
prop_mysterious_1 integer = forAll searchTrees $ \tree ->
  mysteryProp integer tree == (numInt $ mysterious tree)
   where
     numInt = length . filter (== integer)

prop_mysterious_2 :: Property
prop_mysterious_2 = forAll searchTrees $ isSorted . mysterious
----------------------


-- Note `nub` is a function that removes duplicates from a sorted list
sortedListsWithoutDuplicates :: Gen [Integer]
sortedListsWithoutDuplicates = fmap (nub . sort) arbitrary

-- 将一个顺序链表转化成平衡树，忽略重复元素
astonishing :: [Integer] -> BinaryTree
astonishing [] = Leaf
astonishing x = Branch (head r) (astonishing l) (astonishing (tail r))
  where
    (l, r) = splitAt (length x `div` 2) x

{-
prop> prop_astonishing_1
+++ OK, passed 100 tests.
prop> prop_astonishing_2
+++ OK, passed 100 tests.
prop> prop_astonishing_3
+++ OK, passed 100 tests.
-}

-- 检查是否是二叉树以及有没有重复元素
prop_astonishing_1 :: Property
prop_astonishing_1
  = forAll sortedListsWithoutDuplicates $ isBST . astonishing

-- 检查是否是平衡树以及有没有重复元素
prop_astonishing_2 :: Property
prop_astonishing_2
  = forAll sortedListsWithoutDuplicates $ isBalanced . astonishing

-- 将一组数字转成二叉树再转回顺序链表看看还是不是原来的数字
prop_astonishing_3 :: Property
prop_astonishing_3
  = forAll sortedListsWithoutDuplicates $ \ integers ->
    mysterious (astonishing integers) == integers


isBalanced :: BinaryTree -> Bool
isBalanced Leaf = True
isBalanced (Branch v l r) = and [ abs (height l - height r) <= 1
                                , isBalanced l
                                , isBalanced r
                                ]
  where height Leaf = 0
        height (Branch v l r) = 1 + max (height l) (height r)

