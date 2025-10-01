defmodule Hasty.Client do
  @moduledoc """
  A QUIC client.
  """

  alias Hasty.Crypto

  @type target_host ::
          String.t()
          | :inet.hostname()
          | :inet.ip_address()

  @spec connect!(target_host(), :inet.port_number()) :: :inet.socket()
  def connect!(target_host, port) do
    {:ok, client} = connect(target_host, port)
    client
  end

  @spec connect(target_host(), :inet.port_number()) :: {:ok, :inet.socket()} | {:error, any()}
  def connect(target_host, port) when is_integer(port) do
    {:ok, host} = parse_host(target_host)
    {:ok, client} = :gen_udp.open(0)
    {_pub_key, _priv_key} = Crypto.gen_client_exchange_key()
    Crypto.client_initial_keys_calc()

    case :gen_udp.connect(client, host, port) do
      :ok -> {:ok, client}
      error -> {:error, error}
    end
  end

  @spec parse_host(charlist() | binary() | :inet.ip_address()) :: {:ok, :inet.ip_address()}
  defp parse_host(host) when is_list(host), do: :inet.getaddr(host, :inet)
  defp parse_host(host) when is_binary(host), do: host |> String.to_charlist() |> parse_host()

  defp parse_host(host) when is_tuple(host) do
    if :inet.is_ip_address(host) do
      {:ok, host}
    else
      {:error, "Failed to parse provided host IP address / hostname"}
    end
  end
end
