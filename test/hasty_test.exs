defmodule HastyTest do
  use ExUnit.Case

  doctest Hasty
  doctest Hasty.Types.VarInt, import: true
end
