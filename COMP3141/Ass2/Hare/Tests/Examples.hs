module Tests.Examples where
import Data.List
import Tests.Support
import Test.Tasty.HUnit
import Hare 
import Data.Char
import Data.Maybe
test_action_ex_1 = testCase "action example 1" $
    assertEq ("***" =~ Action length (Star (Char ['*'])))
             [3,2,1,0,2,1,0,1,0,0]

test_action_ex_2 = testCase "action example 2" $ 
    assertEq ("AXax" =~ Action isUpper (Char ['a','A']))
             [True, False]
test_action_ex_3 = testCase "action example 3" $ do
    let f (x,y) = [x,y]
    let atoz = Char ['a'..'z']
    assertEq ("ab01cd20" =~ Action f (atoz `Seq` atoz)) ["ab","cd"]

test_cons_ex_1 = testCase "cons example 1" $ do 
    assertEq ("10100" =~ cons (Char ['1']) (Star (Char ['0'])))
             ["10","1","100","10","1"]

test_cons_ex_2 = testCase "cons example 2" $ do 
    assertEq ("10100" =~ cons (Char ['1']) (Action (const []) Empty))
             ["1","1"]

test_plus_ex_1 = testCase "plus example 1" $ do 
    assertEq ("10100" =~ plus (Char ['0'])) 
             ["0","00","0","0"]

test_plus_ex_2 = testCase "plus example 2" $ do 
    let atoz = Char ['a'..'z']
    let digits = Char ['0'..'9']
    assertEq ("ab1c3" =~ plus (atoz `Seq` digits))
             [[('b','1'),('c','3')],[('b','1')],[('c','3')]]

test_string_ex_1 = testCase "string example 1" $ do 
    let comp3141 = string "COMP3141"
    assertEq ("My favourite subject is COMP3141" =~ comp3141) (Just "COMP3141")
test_string_ex_2 = testCase "string example 2" $ do 
    let comp3141 = string "COMP3141"
    assertEq ("My favourite subject is MATH1141" =~ comp3141) Nothing

test_choose_ex_1 = testCase "choose example 1" $ do 
    let re = choose [string "COMP", string "MATH", string "PHYS"]
    assertEq ("COMP3141, MATH1081, PHYS1121, COMP3121" =~ re)
             ["COMP","MATH","PHYS","COMP"]

test_choose_ex_2 = testCase "choose example 2" $ do 
    assertEq ("abc" =~ choose []) (Nothing :: Maybe String)

test_option_ex_1 = testCase "option example 1" $ do 
    let digits = Char ['0'..'9']
    let sign = Action (fromMaybe '+') (option (Char ['-']))
    assertEq ("-30 5 3" =~ (sign `cons` plus digits))
             ["-30","-3","+30","+3","+0","+5","+3"]

test_option_ex_2 = testCase "option example 2" $ do 
    assertEq ("foo" =~ option (Char ['a']))
             [Nothing, Nothing, Nothing, Nothing]

test_rpt_ex_1 = testCase "rpt example 1" $ do 
    let digits = Char ['0'..'9']
    let programs = choose [string "COMP", string "PHYS", string "MATH"]
    let courseCode = programs `Seq` rpt 4 digits 
    assertEq ("COMP3141, MATH1081, and PHYS1121" =~ courseCode)
             [("COMP","3141"),("MATH","1081"),("PHYS","1121")]

test_rpt_ex_2 = testCase "rpt example 2" $ do 
    assertEq ("foo" =~ rpt 0 (Char ['a']))
             (Just "")

test_rptRange_ex_1 = testCase "rptRange example 1" $ do 
    assertEq ("1234" =~ rptRange (2,4) (Char ['0'..'9']))
             ["1234","123","12","234","23","34"]

test_rptRange_ex_2 = testCase "rptRange example 2" $ do 
    assertEq ("1234" =~ rptRange (3,3) (Char ['0'..'9']))
             ["123","234"]
