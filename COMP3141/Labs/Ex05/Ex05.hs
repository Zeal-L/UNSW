module Ex05 where

import Text.Read (readMaybe)

data Token = Number Int | Operator (Int -> Int -> Int)

parseToken :: String -> Maybe Token
parseToken "+" = Just (Operator (+))
parseToken "-" = Just (Operator (-))
parseToken "/" = Just (Operator div)
parseToken "*" = Just (Operator (*))
parseToken str = fmap Number (readMaybe str)

tokenise :: String -> Maybe [Token]
tokenise x = mapM parseToken (words x)

newtype Calc a = C ([Int] -> Maybe ([Int], a))


pop :: Calc Int
pop = C f
  where
    f (x:xs) = Just (xs,x)
    f _      = Nothing


push :: Int -> Calc ()
push i = C $ \xs-> Just (i:xs, ())



instance Functor Calc where
  fmap f (C sa) = C $ \s ->
      case sa s of
        Nothing      -> Nothing
        Just (s', a) -> Just (s', f a)

instance Applicative Calc where
  pure x = C (\s -> Just (s,x))
  C sf <*> C sx = C $ \s ->
      case sf s of
          Nothing     -> Nothing
          Just (s',f) -> case sx s' of
              Nothing      -> Nothing
              Just (s'',x) -> Just (s'', f x)

instance Monad Calc where
  return = pure
  C sa >>= f = C $ \s ->
      case sa s of
          Nothing     -> Nothing
          Just (s',a) -> unwrapCalc (f a) s'
    where unwrapCalc (C a) = a

evaluate :: [Token] -> Calc Int
evaluate [] = pop
evaluate (t:ts) = case t of
  Number   n -> do push n >> evaluate ts
  Operator o -> do y <- pop
                   x <- pop
                   push (o x y)
                   evaluate ts

calculate :: String -> Maybe Int
calculate s = case tokenise s of
  Nothing -> Nothing
  Just ts -> snd <$> unwrapCalc (evaluate ts) []
    where
      unwrapCalc :: Calc a -> [Int] -> Maybe ([Int], a)
      unwrapCalc (C a) = a

