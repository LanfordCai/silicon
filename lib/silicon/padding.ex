defmodule Silicon.Padding do
  @moduledoc false
  defmodule PKCS7 do
    def pad(data, block_size) do
      to_add = block_size - rem(byte_size(data), block_size)
      data <> :binary.copy(<<to_add>>, to_add)
    end

    def unpad(<<>>), do: {:error, :invalid_padding}

    def unpad(data, block_size \\ 16) do
      padding_size = :binary.last(data)
      pt_size = byte_size(data) - padding_size

      with {:ok, padding} <- validate_padding(data, block_size),
           pt = :binary.part(data, 0, pt_size),
           true <- data == pt <> padding do
        pt
      else
        _err -> {:error, :invalid_padding}
      end
    end

    defp validate_padding(data, block_size) do
      padding_size = :binary.last(data)
      data_size = byte_size(data)

      with true <- valid_padding_size?(data_size, block_size, padding_size),
           padding = :binary.part(data, data_size - padding_size, padding_size),
           true <- padding == :binary.copy(<<padding_size>>, padding_size) do
        {:ok, padding}
      else
        _error -> {:error, :invalid_padding}
      end
    end

    defp valid_padding_size?(data_size, block_size, padding_size),
      do: block_size >= padding_size and data_size >= padding_size
  end
end
