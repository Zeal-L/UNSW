{-# OPTIONS_GHC -Wno-incomplete-patterns #-}
-- Zeal L (abc982210694@gmail.com)
-- 2021-06-23 17:15:45
-- Zid: z5325156
--
-- Queue (data refinement) Refinement Relations
{-
    数据细化
    这些类型的属性建立了所谓的数据细化，从抽象的、缓慢的、列表模型到快速的、具体的队列实现。

    细化和规范
    一般来说，所有的功能正确性规范都可以表示为。
    1 所有的数据不变性都被保持，以及
    2 实现是抽象正确性模型的细化。
    在它们变得对测试无用之前，我们可以做的抽象化程度是有限的 测试（但不一定是为了证明）。

    警告
    虽然抽象化可以简化证明，但抽象化并不能降低验证的基本 核查的复杂性，这是很难证明的。
-}

import Test.QuickCheck
    ( vectorOf,
      (==>),
      Arbitrary(arbitrary),
      NonNegative(NonNegative),
      Property )

data Queue = Q [Int] -- front of the queue
               Int   -- size of the front
               [Int] -- rear of the queue
               Int   -- size of the rear
             deriving (Show, Eq)

instance Arbitrary Queue where
  arbitrary = do
    NonNegative sf' <- arbitrary
    NonNegative sr <- arbitrary
    let sf = sf' + sr
    f <- vectorOf sf arbitrary
    r <- vectorOf sr arbitrary
    pure (Q f sf r sr)

-- Amortised Cost
inv3 :: Queue -> Queue
inv3 (Q f sf r sr)
   | sf < sr   = Q (f ++ reverse r) (sf + sr) [] 0
   | otherwise = Q f sf r sr

emptyQueue :: Queue
emptyQueue = Q [] 0 [] 0

enqueue :: Int -> Queue -> Queue
enqueue x (Q f sf r sr) = inv3 (Q f sf (x:r) (sr+1))

front :: Queue -> Int   -- partial, Warning been ignored
front (Q (x:_f) _sf _r _sr) = x

dequeue :: Queue -> Queue -- partial, Warning been ignored
dequeue (Q (_x:f) sf r sr) = inv3 (Q f (sf -1) r sr)

size    :: Queue -> Int
size (Q _f sf _r sr) = sf + sr

-- ! ---------------------------------------------------------------------------
-- Property quickCheck

emptyQueueL :: [a]
emptyQueueL = []
enqueueL :: a -> [a] -> [a]
enqueueL a  = (++ [a])
frontL :: [a] -> a
frontL      = head
dequeueL :: [a] -> [a]
dequeueL    = tail
sizeL :: [a] -> Int
sizeL       = length

wellformed :: Queue -> Bool
wellformed (Q f sf r sr) = length f == sf && length r == sr
                        && sf >= sr

-- 这些细化关系在QuickCheck中很难使用，因为rel fq lq的前提条件很难满足随机生成的输入。
-- 对于这个例子，如果我们定义一个抽象函数来计算 从具体的队列中计算出相应的抽象列表。
-- 所以从概念上讲，我们的细化关系就是。
-- \fq lq -> toAbstract fq == lq
toAbstract :: Queue -> [Int]
toAbstract (Q f _sf r _sr) = f ++ reverse r

prop_empty_ref :: Bool
prop_empty_ref = toAbstract emptyQueue == emptyQueueL

prop_enqueue_ref :: Queue -> Int -> Bool
prop_enqueue_ref fq x = toAbstract (enqueue x fq)
                     == enqueueL x (toAbstract fq)

prop_size_ref :: Queue -> Bool
prop_size_ref fq = size fq == sizeL (toAbstract fq)

prop_front_ref :: Queue -> Property
prop_front_ref fq = size fq > 0 ==> front fq == frontL (toAbstract fq)

prop_deq_ref :: Queue -> Property
prop_deq_ref fq = size fq > 0 ==>  toAbstract (dequeue fq)
                                == dequeueL (toAbstract fq)

{-
    队列的数据不变性
    除了已经说明的细化属性外，我们还有一些数据不变性要维护
    不变量来维护一个值Q f sf r sr。
    1 length f == sf
    2 length r == sr
    3 重要的是：sf ≥ sr --队列的前面不能比后面短。
    我们将确保我们的Arbitrary实例只生成符合这些不变量的值。不变量。
    因此，我们的形式良好的谓词仅仅被用来在我们的操作的输出上强制执行这些数据不变性:
    prop_wf_empty; prop_wf_enq; prop_wf_deq
-}

prop_wf_empty :: Bool
prop_wf_empty = wellformed emptyQueue

prop_wf_enq :: Int -> Queue -> Property
prop_wf_enq x q = wellformed q ==> wellformed (enqueue x q)

prop_wf_deq :: p -> Queue -> Property
prop_wf_deq _x q = wellformed q && size q > 0 ==> wellformed (dequeue q)

{-
prop> prop_empty_ref
+++ OK, passed 1 test.
prop> prop_enqueue_ref
+++ OK, passed 100 tests.
prop> prop_size_ref
+++ OK, passed 100 tests.
prop> prop_front_ref
+++ OK, passed 100 tests; 11 discarded.
prop> prop_deq_ref
+++ OK, passed 100 tests; 10 discarded.
prop> prop_wf_empty
+++ OK, passed 1 test.
prop> prop_wf_enq
+++ OK, passed 100 tests.
>>> import Test.QuickCheck
>>> quickCheck prop_wf_deq
+++ OK, passed 100 tests; 10 discarded.

-}
