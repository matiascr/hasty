defmodule Hasty.Crypto do
  @moduledoc """
  Handles the cryptography needs for the QUIC protocol.

  Credit is owed to https://quic.xargs.org/ for the full explanation and
  examples provided.
  """

  @type key :: binary()

  @type public_key :: key()
  @type private_key :: key()

  @type client_key :: key()
  @type server_key :: key()
  @type client_iv :: key()
  @type server_iv :: key()
  @type client_hp_key :: key()
  @type server_hp_key :: key()

  @initial_salt <<0x38762CF7F55934B34D179AE6A4C80CADCCBB7F0A::size(40 * 8)>>
  @hash_fun :sha256

  @spec gen_client_exchange_key() :: {public_key(), private_key()}
  def gen_client_exchange_key do
    :crypto.generate_key(:ecdh, :x25519)
  end

  @spec client_initial_keys_calc() :: {
          client_key(),
          server_key(),
          client_iv(),
          server_iv(),
          client_hp_key(),
          server_hp_key()
        }
  def client_initial_keys_calc do
    init_dcid = :rand.bytes(8)
    initial_secret = extract(init_dcid, @initial_salt)
    client_secret = expand_label(initial_secret, "client in", 32)
    server_secret = expand_label(initial_secret, "server in", 32)
    client_key = expand_label(client_secret, "quic key", 16)
    server_key = expand_label(server_secret, "quic key", 16)
    client_iv = expand_label(client_secret, "quic iv", 12)
    server_iv = expand_label(server_secret, "quic iv", 12)
    client_hp_key = expand_label(client_secret, "quic hp", 16)
    server_hp_key = expand_label(server_secret, "quic hp", 16)

    {
      client_key,
      server_key,
      client_iv,
      server_iv,
      client_hp_key,
      server_hp_key
    }
  end

  @type hash_fun :: :md5 | :sha | :sha224 | :sha256 | :sha384 | :sha512
  @type input_key_material :: binary
  @type salt :: binary
  @type pseudorandom_key :: binary
  @type length :: non_neg_integer
  @type label :: binary
  @type output_key_material :: binary

  @doc """
  Given a salt and some bytes of key material create 256 bits (32 bytes) of new
  key material, with the input key material's entropy evenly distributed in the
  output.

  ## Example

      iex> init_salt = <<0x0001020304050607::size(8*8)>>
      iex> init_dcid = <<0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a::size(20*8)>>
      iex> Hasty.Crypto.extract(init_salt, init_dcid)
      <<0xf016bb2dc9976dea2726c4e61e738a1e3680a2487591dc76b2aee2ed759822f6::size(32*8)>>

  """
  @spec extract(input_key_material, salt) :: pseudorandom_key
  def extract(key, salt) do
    :hkdf.extract(@hash_fun, salt, key)
  end

  def expand(key, label, len) do
    :hkdf.expand(@hash_fun, key, label, len)
  end

  @doc """
  Given the inputs of key material, label, and context data, create a new key
  of the requested length.

  ## Example

      iex> init_secret = <<0xf016bb2dc9976dea2726c4e61e738a1e3680a2487591dc76b2aee2ed759822f6::size(32*8)>>
      iex> csecret = Hasty.Crypto.expand_label(init_secret, "client in", 32)
      <<0x47c6a638d4968595cc20b7c8bc5fbfbfd02d7c17cc67fa548c043ecb547b0eaa::size(32*8)>>
      iex> ssecret = Hasty.Crypto.expand_label(init_secret, "server in", 32)
      <<0xadc1995b5cee8f03746bf8309d02d5ea27159c1ed6915403b36318d5a03afeb8::size(32*8)>>
      iex> _client_init_key = Hasty.Crypto.expand_label(csecret, "quic key", 16)
      <<0xb14b918124fda5c8d79847602fa3520b::size(16*8)>>
      iex> _server_init_key = Hasty.Crypto.expand_label(ssecret, "quic key", 16)
      <<0xd77fc4056fcfa32bd1302469ee6ebf90::size(16*8)>>
      iex> _client_init_iv = Hasty.Crypto.expand_label(csecret, "quic iv", 12)
      <<0xddbc15dea80925a55686a7df::size(12*8)>>
      iex> _server_init_iv = Hasty.Crypto.expand_label(ssecret, "quic iv", 12)
      <<0xfcb748e37ff79860faa07477::size(12*8)>>
      iex> _client_init_hp = Hasty.Crypto.expand_label(csecret, "quic hp", 16)
      <<0x6df4e9d737cdf714711d7c617ee82981::size(16*8)>>
      iex> _server_init_hp = Hasty.Crypto.expand_label(ssecret, "quic hp", 16)
      <<0x440b2725e91dc79b370711ef792faa3d::size(16*8)>>

  """
  @spec expand_label(pseudorandom_key, label, length, any()) :: output_key_material
  def expand_label(prk, label, length, context \\ "") do
    full_label = "tls13 " <> label
    labellen = byte_size(full_label)
    contextlen = byte_size(context)

    info =
      <<length::16, labellen::8, full_label::binary, contextlen::8, context::binary>>

    expand(prk, info, length)
  end
end
