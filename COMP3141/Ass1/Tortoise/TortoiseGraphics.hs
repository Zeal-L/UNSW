module TortoiseGraphics(drawPicture, writePng) where

import Tortoise (LineStyle (..), Picture, Line(..), Colour(..))

-- Rasterific
import Graphics.Rasterific hiding (Point, Vector, Line, Path)
import Graphics.Rasterific.Texture
import Codec.Picture

-- | Converts a Picture to a JuicyPixels Image than can be saved 
--   with 'writePng' or viewed in the HfM Playground.
drawPicture :: Picture -> Image PixelRGBA8
drawPicture picture 
  = renderDrawing 800 800 (toColour (Colour 0 0 0 255)) $ do
      mapM drawLine picture
      return ()
  where
    style :: LineStyle -> [Primitive] -> Drawing px ()
    style (Solid w)  = stroke (fromIntegral w) JoinRound (CapRound, CapRound)  
    style (Dashed w) = dashed (fromIntegral w) JoinRound (CapRound, CapRound) 
    style (Dotted w) = dotted (fromIntegral w) JoinRound (CapRound, CapRound) 

    dotted w = dashedStroke [w/12, 2 * w] w
    dashed w = dashedStroke [3* w, 6 * w] w

    texture colour = withTexture (uniformTexture $ toColour colour) 

    drawLine (Line lineStyle colour (x1,y1) (x2,y2) ) =
      texture colour
         $ style lineStyle
         $ polyline  [ V2 (fromIntegral x1 + 400) (400 - fromIntegral y1)
                     , V2 (fromIntegral x2 + 400) (400 - fromIntegral y2)
                     ]
           
    toColour (Colour a b c d) 
      = PixelRGBA8 (fromIntegral a) 
                   (fromIntegral b) 
                   (fromIntegral c) 
                   (fromIntegral d)


  
