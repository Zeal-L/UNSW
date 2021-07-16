import Data.List
import System.IO

mazeSize :: Int
mazeSize = 10

data Tile = Wall | Floor deriving (Show, Eq)


type Point = (Int, Int)


lookupMap :: [Tile] -> Point -> Tile
lookupMap ts (x,y) = ts !! (y * mazeSize + x)

addX :: Int -> Point -> Point
addX dx (x,y) = (x + dx, y)

addY :: Int -> Point -> Point
addY dy (x,y) = (x, y + dy)

data Game = G { player :: Point
              , map    :: [Tile]
              }

invariant :: Game -> Bool
invariant (G (x,y) ts) = x >= 0 && x < mazeSize
                      && y >= 0 && y < mazeSize
                      && lookupMap ts (x,y) /= Wall

moveLeft :: Game -> Game
moveLeft (G p m)
  = let g' = G (addX (-1) p) m
     in if invariant g' then g' else G p m

moveRight :: Game -> Game
moveRight (G p m)
  = let g' = G (addX 1 p) m
     in if invariant g' then g' else G p m

moveUp :: Game -> Game
moveUp (G p m)
  = let g' = G (addY (-1) p) m
     in if invariant g' then g' else G p m

moveDown :: Game -> Game
moveDown (G p m)
  = let g' = G (addY 1 p) m
     in if invariant g' then g' else G p m

won :: Game -> Bool
won (G p m) = p == (mazeSize-1,mazeSize-1)

main :: IO ()
main = do
    str <- readFile "GameInput.txt"
    let initial = G (0,0) (stringToMap str)
    gameLoop initial
  where
    gameLoop :: Game -> IO ()
    gameLoop state
        | won state = putStrLn "You win!"
        | otherwise = do
            display state
            c <- getChar'
            case c of
                'w' -> gameLoop (moveUp state)
                'a' -> gameLoop (moveLeft state)
                's' -> gameLoop (moveDown state)
                'd' -> gameLoop (moveRight state)
                'q' -> pure ()
                _   -> gameLoop state

stringToMap :: String -> [Tile]
stringToMap [] = []
stringToMap ('#':xs) = Wall : stringToMap xs
stringToMap (' ':xs) = Floor : stringToMap xs
stringToMap (c:xs)   = stringToMap xs

display :: Game -> IO ()
display (G (px,py) m) = printer (0,0) m
  where
    printer (x,y) (t:ts) = do
        if (x,y) == (px,py) then putChar '@'
        else if t == Wall then putChar '#'
        else putChar ' '

        if (x == mazeSize - 1) then do
            putChar '\n'
            printer (0,y+1) ts
        else printer (x+1,y) ts
    printer (x,y) [] = putChar '\n'

getChar' :: IO Char
getChar' = do
    b <- hGetBuffering stdin
    e <- hGetEcho stdin
    hSetBuffering stdin NoBuffering
    hSetEcho stdin False
    x <- getChar
    hSetBuffering stdin b
    hSetEcho stdin e
    pure x