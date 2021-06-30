--  Zeal L (abc982210694@gmail.com)
--  2021-06-19 06:34:27
--  Zid: z5325156
--
--  判断是否可以从杂志中剪取制作勒索信所需要的字母

import qualified Data.Map as M

type RansomNote = String
type Magazine = String

-- Specification 初步实现，不确定是否可靠
canMakeRansomSpec :: RansomNote -> Magazine -> Bool
canMakeRansomSpec note magazine = all enoughChars note
  where
    enoughChars :: Char -> Bool
    enoughChars c = countChars c note <= countChars c magazine

    countChars :: Char -> String -> Int
    countChars c = length . filter (== c)

-- ! ---------------------------------------------------------------------------

-- Efficient implementation 更可靠 表现更好 复杂度更低的实现
canMakeRansom :: RansomNote -> Magazine -> Bool
canMakeRansom note magazine = countChars' note <= countChars' magazine

-- Get the total number of each character in a string
newtype Counts = Counts (M.Map Char Int) deriving (Eq, Show)

-- 函数isSubmapOfBy:
-- 如果sub中的所有keys都在super中，并且当f应用到它们各自的值时返回True。
instance Ord Counts where
  (Counts sub) <= (Counts super) = M.isSubmapOfBy (<=) sub super

-- An empty collection of character counts
emptyCounts :: Counts
emptyCounts = Counts M.empty

countChars' :: String -> Counts
countChars' = foldr increment emptyCounts
  where
    increment :: Char -> Counts -> Counts
    -- 函数alter: 用inc改变c处的值x，或者不改变其值。
    -- 改变可以用来插入、删除或更新counts中的一个值。
    increment c (Counts counts) = Counts $ M.alter inc c counts

    inc :: Maybe Int -> Maybe Int
    inc Nothing      = Just 1
    inc (Just tally) = Just $ tally + 1

-- ! ---------------------------------------------------------------------------

{- Refinement property 测试初步实现的完整性及规范性
    以函数应满足哪些属性的形式提供程序的规范，
    QuickCheck 将测试这些属性是否存在于大量随机生成的案例中

prop> prop_canMakeRansomRefine
+++ OK, passed 100 tests.

-}
prop_canMakeRansomRefine :: RansomNote -> Magazine -> Bool
prop_canMakeRansomRefine note magazine
  = canMakeRansom note magazine == canMakeRansomSpec note magazine
