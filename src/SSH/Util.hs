module SSH.Util where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS


toLBS :: String -> LBS.ByteString
toLBS = LBS.pack . map (fromIntegral . fromEnum)

fromLBS :: LBS.ByteString -> String
fromLBS = map (toEnum . fromIntegral) . LBS.unpack

strictLBS :: LBS.ByteString -> BS.ByteString
strictLBS = BS.concat . LBS.toChunks
