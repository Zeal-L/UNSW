module Main where
import Test.Tasty (defaultMain, testGroup)
import Tests.Transcript
import Tests.UnitTests
import Tests.Examples

tests = testGroup "all tests" [
  testGroup "transcript acceptance tests" [
    testGroup "basic match tests" [
       test_empty, test_fail, test_courseCodesRaw, test_grades, test_firstname
    ],
    testGroup "action tests" [
      test_courseCodes, test_grades
    ],
    testGroup "combinator tests" [
      test_decimalNumber, test_gradeRecords, test_tortoiseCourseCodes,
      test_gradesAlt, test_studentNumber, test_stars
    ]
  ],
  testGroup "unit tests and properties" [
    testGroup "empty" [ test_empty_maybe, test_empty_list ],
    testGroup "fail"  [ test_fail_maybe,  test_fail_list  ],
    testGroup "char"  [ test_char_filter, test_char_maybe ],
    testGroup "seq"   [ test_seq_1, test_seq_2, test_seq_3, test_seq_4, test_seq_5],
    testGroup "cho"   [ test_ch_1, test_ch_2, test_ch_3, test_ch_4, test_ch_5],
    testGroup "star"  [ test_star_1,test_star_2, test_star_3]
  ],
  testGroup "spec examples" [
    testGroup "action" [test_action_ex_1, test_action_ex_2, test_action_ex_3 ],
    testGroup "cons"   [test_cons_ex_1, test_cons_ex_2],
    testGroup "plus"   [test_plus_ex_1, test_plus_ex_2],
    testGroup "string" [test_string_ex_1, test_string_ex_2],
    testGroup "choose" [test_choose_ex_1, test_choose_ex_2],
    testGroup "option" [test_option_ex_1, test_option_ex_2],
    testGroup "rpt"    [test_rpt_ex_1, test_rpt_ex_2],
    testGroup "rptRange" [test_rptRange_ex_1, test_rptRange_ex_2]
  ]
  ]

main = defaultMain tests
