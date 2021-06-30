module ShapeGraphics (
  drawPicture, 
  Point(..), 
  Vector(..), 
  Line(..), 
  Picture, 
  Colour (..), 
  LineStyle (..), 
  FillStyle (..), 
  PictureObject(..),
  white, black, blue, red, green, yellow, magenta, orange
) where
 
  -- Rasterific
import Graphics.Rasterific hiding (Point, Vector, Line, Path)
import Graphics.Rasterific.Texture
import Graphics.Rasterific.Transformations


 
import Codec.Picture
 
data Colour 
  = Colour 
    { redC      :: Int
    , greenC    :: Int
    , blueC     :: Int
    , opacityC  :: Int
    }
  deriving (Show, Eq)
 
white      = Colour 255  255 255 255
black      = Colour   0    0   0 255
blue       = Colour   0    0 255 255
red        = Colour 255    0   0 255
green      = Colour  10  255  10 235
yellow     = Colour  255 255   0 235
magenta    = Colour 153    0 153 255
orange     = Colour 254  154  46 255


data Point 
  = Point 
    { xPoint :: Float
    , yPoint :: Float
    } deriving (Show, Eq)

data Vector 
  = Vector
    { xVector :: Float
    , yVector :: Float
    } deriving (Show, Eq)

      
data Line    
  = Line 
    { startLine :: Point
    , endLine   :: Point
    } deriving (Show, Eq)



data LineStyle 
  = Solid
  | Dashed
  | Dotted
  deriving (Show, Eq)

data FillStyle
  = NoFill
  | SolidFill
   deriving (Eq, Show)
  
 
data PictureObject 
  = Path    
    { pointsPO    :: [Point] 
    , colourPO    :: Colour
    , lineStylePO :: LineStyle
    }
  | Circle  
    { centerPO    :: Point
    , radiusPO    :: Float
    , colourPO    :: Colour
    , lineStylePO :: LineStyle
    , fillStylePO :: FillStyle 
    }
  | Ellipse
    { centerPO    :: Point
    , widthPO     :: Float
    , heightPO    :: Float
    , rotationPO  :: Float
    , colourPO    :: Colour
    , lineStylePO :: LineStyle
    , fillStylePO :: FillStyle
    }
  | Polygon 
    { pointsPO    :: [Point]
    , colourPO    :: Colour
    , lineStylePO :: LineStyle
    , fillStylePO :: FillStyle 
    }  deriving (Show, Eq)


type Picture = [PictureObject]


drawPicture linewidth picture 
  = renderDrawing  800 800 (toColour (Colour 0 0 0 255)) $ do
      { mapM drawObj picture
      ; return ()
      }
  where
    style SolidFill _ = fill
    style _ Solid     = stroke linewidth  JoinRound (CapRound, CapRound)  
    style _ Dashed    = dashed linewidth  JoinRound (CapRound, CapRound) 
    style _ Dotted    = dotted linewidth  JoinRound (CapRound, CapRound) 

    dotted = dashedStroke [linewidth/12, 2 * linewidth]
    dashed = dashedStroke [3* linewidth, 6 * linewidth] 

    texture colour = withTexture (uniformTexture $ toColour colour) 
    textureG  (x1, y1) (x2, y2) 
      = withTexture (linearGradientTexture  
          [(0, PixelRGBA8 255 0 0 255), (1, PixelRGBA8 255 255 255 255)] 
                (V2 x1 y1)(V2 x2 y2))   
    drawObj (Path points colour lineStyle) =
      texture colour
         $ style NoFill lineStyle
         $ polyline 
         $ map (\((Point x y)) -> V2 x y) points
    drawObj (Circle (Point px py) radius colour lineStyle fillStyle) =
      texture colour
         $ style fillStyle lineStyle
         $ circle (V2 px py) radius
    drawObj (Ellipse (Point px py) h w r colour lineStyle fillStyle) =
      texture colour
         $ style fillStyle lineStyle 
           . transform (applyTransformation 
                       $ rotateCenter r (V2 px py))
         $ ellipse (V2 px py) h w
    drawObj (Polygon points colour lineStyle fillStyle) =
      texture colour
         $ style fillStyle lineStyle
         $ polygon 
         $ map (\((Point x y)) -> V2 x y) points
           

    toColour (Colour a b c d) 
      = PixelRGBA8 (fromIntegral a) (fromIntegral b) (fromIntegral c) (fromIntegral d)

