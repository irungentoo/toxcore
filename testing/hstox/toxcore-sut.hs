module Main (main) where

import           Control.Concurrent  (threadDelay)
import           System.Environment  (getArgs, withArgs)
import           System.Process      (createProcess, proc, terminateProcess)

import           Network.Tox.Testing (serve)
import qualified ToxTestSuite


foreign import ccall test_main :: IO ()


main :: IO ()
main = do
  args <- getArgs
  case args of
    ["--sut"] -> test_main
    self : testArgs -> do
      -- Start a toxcore SUT (System Under Test) process that will listen on
      -- port 1234. We call ourselves here, so the branch above is taken.
      (_, _, _, sut) <- createProcess $ proc self ["--sut"]
      -- 100ms delay to give the SUT time to set up its socket before we try to
      -- build connections in the test runner.
      threadDelay $ 100 * 1000
      -- ToxTestSuite (the test runner) makes connections to port 1234 to
      -- communicate with the SUT.
      withArgs (["--print-cpu-time", "--color"] ++ testArgs) ToxTestSuite.main
      terminateProcess sut
    _ ->
      fail "Usage: toxcore-sut <path-to-toxcore-sut> [test-args...]"
