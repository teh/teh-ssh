{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent (forkIO, killThread, threadDelay, forkFinally)
import           Control.Exception (bracket)
import qualified Control.Foldl as Fold
import           Control.Monad (when)
import           Data.Text (pack)
import           Network (listenOn, PortID(..))
import qualified Network.Socket as NS
import qualified SSH as SSH
import qualified SSH.Channel as Channel
import qualified SSH.Crypto as Crypto
import qualified SSH.Session as Session
import           Test.Tasty
import           Test.Tasty.HUnit
import qualified Turtle as T
import qualified Turtle.Prelude as T
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar, MVar)

-- | Returns a free port for use in testing. Picking a specific port
-- doesn't e.g. allow running two tests in parallel and could also
-- collide with other things running on the host.
getFreeSock :: IO (NS.PortNumber, NS.Socket)
getFreeSock = do
    sock <- listenOn (PortNumber 0)
    port <- NS.socketPort sock
    print port
    return (port, sock)


main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "All Tests"
    [ testKeys
    , testLoop
    ]

testKeys :: TestTree
testKeys = testGroup "keys"
    [ testCase "readPrivkey" $ do
           Crypto.RSAKeyPair (Crypto.RSAPublicKey e n) d <- Crypto.rsaKeyPairFromFile "./tests/test_keypair_ok"
           assertBool "invalid E" (e > 0)
           assertBool "invalid N" (n > 0)
           assertBool "invalid D" (d > 0)
    ]



type SetupT = (NS.PortNumber,
               NS.Socket,
               Session.SessionConfig,
               Channel.ChannelConfig)

testLoop :: TestTree
testLoop = testGroup "loop"
    [ testCase "runLoop" (bracket setUp tearDown actualTest)
    ]
  where
    sshAuthorize auth = return True
    channelRequest wr request = do
        Channel.channelMessage "line 1"
        Channel.channelMessage "line 2"
        Channel.channelSuccess
        Channel.channelDone

    setUp :: IO SetupT
    setUp = do
        kp <- Crypto.rsaKeyPairFromFile "./tests/test_keypair_ok"
        (port, sock) <- getFreeSock
        let sConf = Session.SessionConfig ["publickey"] sshAuthorize kp
        let cConf = Channel.ChannelConfig channelRequest
        return (port, sock, sConf, cConf)

    tearDown :: SetupT -> IO ()
    tearDown (port, sock, sConf, cConf) = do
        NS.sClose sock

    tryLogin :: NS.PortNumber -> IO Int
    tryLogin port = do
        o <- T.fold (T.inproc "ssh"
                [ "127.1"
                , "-p"
                , (pack (show port))
                , "-o", "StrictHostKeyChecking=no"
                ] T.empty)
          Fold.length
        return o

    actualTest :: SetupT -> IO ()
    actualTest (port, sock, sConf, cConf) = do
        tid <- forkIO $ SSH.waitLoop sConf cConf sock
        o <- tryLogin port
        assertBool "Did not receive 2 lines from SSH" (o == 2)
        killThread tid

    -- xx <- x
