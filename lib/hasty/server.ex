defmodule Hasty.Server do
  @moduledoc """
  A QUIC server.
  """

  alias Hasty.Spec

  require Logger

  @spec start(:inet.port_number()) :: {:start_error, any()} | :exit
  def start(port) when is_integer(port) do
    case :gen_udp.open(port) do
      {:ok, socket} -> loop(socket)
      {:error, error} -> {:start_error, error}
    end
  end

  defp loop(socket) do
    receive do
      {:udp, socket, _peer_ip, _peer_port, packet} ->
        case parse_packet(packet) do
          {:initial_packet, client_data} -> server_hello(socket, client_data)
          _ -> nil
        end

        loop(socket)

      {:udp, _socket, _peer_ip, _peer_port, _anc_data, packet} ->
        Logger.info("Unknown packet with ancillary data received: #{packet}")
        loop(socket)

      :kill ->
        :gen_udp.close(socket)

      data ->
        Logger.info("Received data #{data}", [:module])
        :gen_udp.close(socket)
        :exit
    end
  end

  @spec parse_packet(binary()) :: {:initial_packet | :version_negotiation_packet | atom(), term()}
  def parse_packet(packet) do
    cond do
      Spec.is_initial_packet?(packet) -> Spec.parse_initial_packet(packet)
      Spec.is_long_header_packet?(packet) -> nil
    end

    packet
  end

  def server_hello(_socket, _client_data) do
  end

  def accept(_listener), do: nil
  def handshake(_connection), do: nil
  def accept_stream(_connection), do: nil
  def close(connection), do: :gen_udp.close(connection)
end
