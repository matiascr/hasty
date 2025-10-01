defmodule ClientTest do
  use ExUnit.Case

  alias Hasty.Client
  alias Hasty.Server

  @port 1234

  describe "start client" do
    test "using hostname" do
      pid = spawn(fn -> Server.start(@port) end)
      assert {:ok, port} = Client.connect("localhost", @port)
      assert is_port(port)

      Process.exit(pid, :kill)
    end

    test "using ip string" do
      pid = spawn(fn -> Server.start(@port) end)
      assert {:ok, port} = Client.connect("127.0.0.1", @port)
      assert is_port(port)

      Process.exit(pid, :kill)
    end

    test "using ip tuple" do
      pid = spawn(fn -> Server.start(@port) end)
      assert {:ok, port} = Client.connect({127, 0, 0, 1}, @port)
      assert is_port(port)

      Process.exit(pid, :kill)
    end
  end
end
