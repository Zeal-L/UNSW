module Tests.Transcript where
import Hare
import Tests.Support
import Data.List(inits,reverse)

data GradeRecord = R String (Maybe Int) String deriving (Eq,Show)

reDecimalNumber
  = wrap $ Action (\((w,p),d) -> read (w ++ p : d) :: Double) $ 
      plus digits `Seq` Char ['.'] `Seq` plus digits
    where 
      digits = Char ['0'..'9']  
      -- Expect spaces before and after to remove partial matches
      -- Gets rid of numbers at the end of lines too but meh.
      wrap re = Action (\((_,r),_) -> r) (Char [' '] `Seq` re `Seq` Char [' '])
reStudentNumber 
  = rpt 7 (Char ['0'..'9'])
reGradeRecords
  = Action (\((c,m),g) -> R c m g) $
          (reCourseCodes `seqFst` Star printable)
    `Seq` (reDecimalNumber `Seq` spaces `Seq` reDecimalNumber `Seq` spaces 
           `seqSnd` option (numbers `seqFst` spaces))
    `Seq` reGrades
  where
    printable = Char [' '..'~'] -- every printable ASCII character.
    spaces = Star (Char [' '])

    seqFst :: RE a -> RE b -> RE a 
    seqFst a b = Action fst (a `Seq` b)

    seqSnd :: RE a -> RE b -> RE b 
    seqSnd  a b = Action snd (a `Seq` b)

    numbers :: RE Int
    numbers = Action read (plus (Char ['0'..'9']))

reStars = Char [' '] `seqSnd` rptRange (1,10) (Char ['*']) `seqFst` Char ['\n']
  where
    seqFst :: RE a -> RE b -> RE a 
    seqFst a b = Action fst (a `Seq` b)

    seqSnd :: RE a -> RE b -> RE b 
    seqSnd  a b = Action snd (a `Seq` b)

reCourseCodesRaw = caps `Seq` caps `Seq` caps `Seq` caps 
            `Seq` digits `Seq` digits `Seq` digits `Seq` digits 
  where caps = Char ['A'..'Z']
        digits = Char ['0'..'9']

reCourseCodes = Action fromRaw reCourseCodesRaw 
  where fromRaw ((((((((c,o),m),p),a),b),x),y)) = [c,o,m,p,a,b,x,y]

reGradesRaw = (Char ['H'] `Seq` Char ['D'])
     `Choose` (Char ['D'] `Seq` Char ['N'])
     `Choose` (Char ['C'] `Seq` Char ['R'])
     `Choose` (Char ['P'] `Seq` Char ['S'])
     `Choose` (Char ['F'] `Seq` Char ['L'])
     `Choose` (Char ['A'] `Seq` Char ['F'])
     `Choose` (Char ['S'] `Seq` Char ['Y'])
     `Choose` (Char ['E'] `Seq` Char ['C'])
     `Choose` (Char ['R'] `Seq` Char ['C'])

reGrades = Action fromRaw reGradesRaw 
  where fromRaw (a,b) = [a,b]

reTortoiseCourseCodes = Action fst (reCourseCodes `Seq` string " Tortoise") 
  
reGradesAlt = choose 
  [ string "HD"
  , string "DN"
  , string "CR"
  , string "PS"
  , string "FL"
  , string "AF"
  , string "SY"
  , string "EC"
  , string "RC"
  ]

test_empty = testRE "Empty" Empty "Tests/transcript.txt" (replicate 5102 ())

test_fail = testRE "Fail" (Fail :: RE ()) "Tests/transcript.txt" []

test_courseCodesRaw
   = testRE "raw course codes (Seq, Char)" 
            reCourseCodesRaw "Tests/transcript.txt" (map toRaw transcriptCodes)
  where 
      toRaw [c,o,m,p,a,b,x,y] = ((((((((c,o),m),p),a),b),x),y))

test_courseCodes
   = testRE "course codes (Seq, Char, Action)" 
            reCourseCodes "Tests/transcript.txt" transcriptCodes

test_tortoiseCourseCodes
   = testRE "course codes for names starting with Tortoise (string)" 
            reTortoiseCourseCodes "Tests/transcript.txt" 
            ["SHEL1603","TORT1927","TORT4181","TORT4418"]
test_gradesRaw 
  = testRE "raw grades (Seq, Char, Choose)" 
           reGradesRaw "Tests/transcript.txt" (map toRaw transcriptGrades)
  where 
     toRaw [a,b] = (a,b)

test_grades
  = testRE "raw grades (Seq, Char, Choose, Action)" 
           reGrades "Tests/transcript.txt" transcriptGrades
test_gradesAlt 
  = testRE "grades using combinators (string, choose)"
           reGradesAlt "Tests/transcript.txt" transcriptGrades
test_firstname        
  = testRE "first name inits (Char, Seq, Star)" 
            regex "Tests/transcript.txt" expected
  where regex = (Char [','] `Seq` Star printable)
        printable = Char [' '..'~'] -- every printable ASCII character.
        expected = map ((,) ',') (reverse (inits " Simon The"))

test_gradeRecords
  = testRE "grade records (option, plus)"
           reGradeRecords "Tests/transcript.txt" transcriptGradeRecords
test_decimalNumber
  = testRE "decimal numbers (plus)" 
           reDecimalNumber "Tests/transcript.txt" transcriptDecimalNumbers
test_studentNumber 
  = testRE "student number (rpt)"
           reStudentNumber "Tests/transcript.txt" ["4444444"]
test_stars 
  = testRE "stars (rptRange)"
           reStars "Tests/transcript.txt" 
           ["********","******","********","****","****","*****","******"
           ,"********","*****","*****","****"]

transcriptCodes = 
  [ "TORT1917", "SHEL1603", "TURT1000", "MATH1131",
    "TORT1927", "TURT1001", "MATH1231",
    "TURT2630", "TORT2041", "TORT2121", "TORT2911",
    "TURT2631", "TORT3161",
    "COMP3141", "TORT3901",
    "TORT3151", "TORT4181",
    "TORT3131", "TORT3411", "TORT4141",
    "TORT3171", "TORT4161", "TORT4418", "MATH1081",
    "TORT3891", "TORT4910", "TORT6721",
    "TORT4911", "TORT4920",
    "TORT3902", 
    "TORT6752", "TORT9153", "TORT9902",
    "TORT9902", "GSOE9400",
    "TORT9902", "GSOE9400",
    "TORT9902",
    "TORT9902",
    "TORT9902",
    "TORT9902",
    "TORT9902" ]
transcriptGrades = 
  ["HD","CR","DN","PS"
  ,"HD","PS","PS"
  ,"PS","HD","CR","HD"
  ,"PS","HD"
  ,"HD","HD"
  ,"HD","HD"
  ,"HD","DN","CR"
  ,"HD","HD","HD","PS"
  ,"HD","SY","HD"
  ,"HD","DN"
  ,"HD"
  ,"HD","HD","RC"
  ,"RC","EC"
  ,"RC","SY"
  ,"RC","RC","RC","RC","RC"]
transcriptDecimalNumbers = 
  [6.0,6.0,6.0,6.0,6.0,6.0,6.0,6.0,76.75,24.0
  ,6.0,6.0,6.0,6.0,6.0,6.0,71.0,42.0
  ,6.0,6.0,6.0,6.0,6.0,6.0,6.0,6.0,76.0,24.0
  ,6.0,6.0,6.0,6.0,72.5,12.0
  ,6.0,6.0,6.0,6.0,95.5,12.0
  ,6.0,6.0,6.0,6.0,90.5,12.0
  ,6.0,6.0,6.0,6.0,6.0,6.0,78.333,18.0
  ,6.0,6.0,6.0,6.0,6.0,6.0,6.0,6.0,82.75,24.0
  ,6.0,6.0,3.0,3.0,6.0,6.0,86.5,15.0
  ,15.0,15.0,6.0,6.0,90.0,21.0
  ,12.0,12.0,93.0,12.0
  ,82.691,192.0
  ,0.0,0.0,0.0,0.0,24.0,0.0,24.0
  ,24.0,0.0,0.0,0.0,24.0
  ,24.0,0.0,0.0,0.0,24.0
  ,24.0,0.0,24.0
  ,24.0,0.0,24.0
  ,24.0,0.0,24.0
  ,24.0,0.0,24.0
  ,24.0,0.0,24.0
  ,0.0,192.0]
transcriptGradeRecords =
  [R "TORT1917" (Just 94) "HD",R "SHEL1603" (Just 74) "CR"
  ,R "TURT1000" (Just 80) "DN",R "MATH1131" (Just 59) "PS"
  ,R "TORT1927" (Just 98) "HD",R "TURT1001" (Just 58) "PS"
  ,R "MATH1231" (Just 57) "PS",R "TURT2630" (Just 56) "PS"
  ,R "TORT2041" (Just 90) "HD",R "TORT2121" (Just 69) "CR"
  ,R "TORT2911" (Just 89) "HD",R "TURT2631" (Just 54) "PS"
  ,R "TORT3161" (Just 91) "HD",R "COMP3141" (Just 93) "HD"
  ,R "TORT3901" (Just 98) "HD",R "TORT3151" (Just 87) "HD"
  ,R "TORT4181" (Just 94) "HD",R "TORT3131" (Just 89) "HD"
  ,R "TORT3411" (Just 75) "DN",R "TORT4141" (Just 71) "CR"
  ,R "TORT3171" (Just 85) "HD",R "TORT4161" (Just 100) "HD"
  ,R "TORT4418" (Just 86) "HD",R "MATH1081" (Just 60) "PS"
  ,R "TORT3891" (Just 86) "HD",R "TORT4910" Nothing "SY"
  ,R "TORT6721" (Just 87) "HD",R "TORT4911" (Just 96) "HD"
  ,R "TORT4920" (Just 75) "DN",R "TORT3902" (Just 93) "HD"
  ,R "TORT6752" (Just 89) "HD",R "TORT9153" (Just 86) "HD"
  ,R "TORT9902" Nothing "RC",R "TORT9902" Nothing "RC"
  ,R "GSOE9400" Nothing "EC",R "TORT9902" Nothing "RC"
  ,R "GSOE9400" Nothing "SY",R "TORT9902" Nothing "RC"
  ,R "TORT9902" Nothing "RC",R "TORT9902" Nothing "RC"
  ,R "TORT9902" Nothing "RC",R "TORT9902" Nothing "RC"]