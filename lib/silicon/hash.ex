defmodule Silicon.Hash do
  @moduledoc """
  """

  [224, 256, 384, 512]
  |> Enum.map(&[&1, {:"sha#{&1}", :"sha3_#{&1}", :"keccak_#{&1}", :"blake2b_#{&1}"}])
  |> Enum.each(fn [bits, {sha2_func, sha3_func, keccak_func, blake2b_func}] ->
    bytes = div(bits, 8)

    @spec unquote(sha2_func)(binary()) :: binary()
    def unquote(sha2_func)(data), do: :crypto.hash(unquote(sha2_func), data)

    @spec unquote(sha3_func)(binary()) :: binary()
    def unquote(sha3_func)(data), do: apply(:libdecaf, unquote(sha3_func), [data])

    @spec unquote(keccak_func)(binary()) :: binary()
    def unquote(keccak_func)(data), do: apply(:keccakf1600, unquote(sha3_func), [data])

    @spec unquote(blake2b_func)(
            binary(),
            binary(),
            keyword()
          ) :: binary()
    def unquote(blake2b_func)(data, key \\ <<>>, options \\ []) do
      salt = options[:salt] || <<>>
      personal = options[:personal] || <<>>

      Blake2.Blake2b.hash(data, key, unquote(bytes), salt, personal)
    end
  end)

  @spec md5(binary()) :: binary()
  def md5(data), do: :crypto.hash(:md5, data)

  @spec ripemd160(binary()) :: binary()
  def ripemd160(data), do: :crypto.hash(:ripemd160, data)

  @spec hash160(binary()) :: binary()
  def hash160(data), do: data |> sha256() |> ripemd160()

  @spec double_sha256(binary()) :: binary()
  def double_sha256(data), do: data |> sha256() |> sha256()
end
