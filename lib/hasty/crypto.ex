defmodule Hasty.Crypto do
  @moduledoc false

  @type key :: binary()

  @type public_key :: key()
  @type private_key :: key()

  @type client_key :: key()
  @type server_key :: key()
  @type client_iv :: key()
  @type server_iv :: key()
  @type client_hp_key :: key()
  @type server_hp_key :: key()

  @initial_salt "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
  @hash_len 32
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
    client_secret = expand(initial_secret, 32, "client in")
    server_secret = expand(initial_secret, 32, "server in")
    client_key = expand(client_secret, 16, "quic key")
    server_key = expand(server_secret, 16, "quic key")
    client_iv = expand(client_secret, 12, "quic iv")
    server_iv = expand(server_secret, 12, "quic iv")
    client_hp_key = expand(client_secret, 16, "quic hp")
    server_hp_key = expand(server_secret, 16, "quic hp")

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
  @type info :: binary
  @type output_key_material :: binary

  @spec extract(input_key_material, salt) :: pseudorandom_key
  def extract(key, salt) do
    :crypto.mac(:hmac, @hash_fun, salt, key)
  end

  @spec expand(pseudorandom_key, length, info) :: output_key_material
  def expand(key, len, info) do
    n = (len / @hash_len) |> Float.ceil() |> round()

    1..n
    |> Enum.scan("", fn index, prev ->
      data = prev <> info <> <<index>>
      :crypto.mac(:hmac, @hash_fun, key, data)
    end)
    |> Enum.join()
    |> binary_slice(0..(len - 1))
  end
end
