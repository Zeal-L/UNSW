module Tests.Support where
import Test.Tasty (TestName, TestTree)
import Test.Tasty.HUnit
import Hare

testRE :: (Eq a, Show a) => TestName -> RE a -> FilePath -> [a] -> TestTree
testRE n re fp rs =
   testCase n $ do
     corpus <- readFile fp
     assertEqual "" rs (corpus =~ re)

assertEq :: (Eq a, Show a) => a -> a -> Assertion 
assertEq = flip (assertEqual "")