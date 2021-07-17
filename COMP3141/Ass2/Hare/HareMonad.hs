module HareMonad
  ( Hare
  , hare
  , failure
  , readCharacter
  ) where 

import Control.Applicative

newtype Hare f a
    = Hare { runHare :: String -> f (String, a) }

hare :: Functor f => Hare f a -> String -> f a 
hare a s = fmap snd (runHare a s)

instance Functor f => Functor (Hare f) where 
    fmap f (Hare a) = Hare $ \s -> 
        fmap (fmap f) (a s)

instance Monad f => Applicative (Hare f) where 
    pure x = Hare $ \s -> pure (s, x)
    Hare f <*> Hare x = Hare $ \s -> do 
        (s',rf)  <- f s 
        (s'',rx) <- x s'
        return (s'', rf rx)

instance Monad f => Monad (Hare f) where 
    return x = pure x 
    Hare a >>= f = Hare $ \s -> do
        (s', ra) <- a s
        let (Hare f') = f ra
        (s'', rf) <- f' s'
        pure (s'', rf)

instance (Monad f, Alternative f) => Alternative (Hare f) where 
    empty = Hare (const empty)
    Hare a <|> Hare b = Hare $ \s -> a s <|> b s


failure :: (Alternative f, Monad f) => Hare f a
failure = empty

readCharacter :: (Alternative f, Monad f) => Hare f Char
readCharacter = Hare $ \s -> case s of 
     [] -> empty
     (x:xs) -> pure (xs,x)
