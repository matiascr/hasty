defmodule Hasty.Types.VarInt do
  @moduledoc """
  Implements the variable-length integer specification of QUIC.
  Refer to [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc) for more details.
  """

  @size_00 2 ** 6
  @size_01 2 ** 14
  @size_10 2 ** 30
  @size_11 2 ** 62

  @doc """
  Returns the length of the given varint (in number of bytes).

  # Examples

        iex> Hasty.Types.VarInt.length(<<0x12>>)
        1

        iex> Hasty.Types.VarInt.length(<<0x81, 0x0C, 0xA0, 0x00>>)
        4
  """
  @spec length(bitstring()) :: pos_integer()
  def length(<<0b00::2, _::bitstring>>), do: 1
  def length(<<0b01::2, _::bitstring>>), do: 2
  def length(<<0b10::2, _::bitstring>>), do: 4
  def length(<<0b11::2, _::bitstring>>), do: 8
  def length(_), do: raise(ArgumentError)

  @doc """
  Encodes a given integer into the QUIC variable length integer format.

  # Examples

        iex> encode(12)
        <<0b00::2, 12::6>>

        iex> encode(64)
        <<0b01::2, 64::14>>
  """
  @spec encode(non_neg_integer()) :: binary()
  def encode(n) when is_integer(n) and n > 0 and n < @size_00, do: <<0b00::2, n::6>>
  def encode(n) when is_integer(n) and n > 0 and n < @size_01, do: <<0b01::2, n::14>>
  def encode(n) when is_integer(n) and n > 0 and n < @size_10, do: <<0b10::2, n::30>>
  def encode(n) when is_integer(n) and n > 0 and n < @size_11, do: <<0b11::2, n::62>>

  @doc """
  Decodes a given variable length integer into the value contained and the rest of the binary given.

  # Examples

        iex> decode(<<0b00::2, 12::6>>)
        {12, <<>>}

        iex> decode(<<0b01::2, 64::14, 0x123::8>>)
        {64, <<0x123::8>>}
  """
  @spec decode(bitstring()) :: {pos_integer(), bitstring()}
  def decode(<<0b00::2, n::6, rest::bitstring>>), do: {n, <<rest::bitstring>>}
  def decode(<<0b01::2, n::14, rest::bitstring>>), do: {n, <<rest::bitstring>>}
  def decode(<<0b10::2, n::30, rest::bitstring>>), do: {n, <<rest::bitstring>>}
  def decode(<<0b11::2, n::62, rest::bitstring>>), do: {n, <<rest::bitstring>>}
  def decode(_), do: raise(ArgumentError)
end
