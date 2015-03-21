module Main where

import qualified SSH as SSH
import qualified SSH.Crypto as Crypto
import           Test.Tasty
import           Test.Tasty.HUnit

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "All Tests"
    [ testKeys
    ]

testKeys :: TestTree
testKeys = testGroup "keys"
    [ testCase "readPrivkey" $ do
           Crypto.RSAKeyPair (Crypto.RSAPublicKey e n) d <- Crypto.rsaKeyPairFromFile "./tests/test_keypair_ok"
           assertBool "invalid E" (e > 0)
           assertBool "invalid N" (n > 0)
           assertBool "invalid D" (d > 0)
    ]
