defmodule Silicon.Hash do
  # Define sha2, sha3, origin keccak and blake2b functions
  [224, 256, 384, 512]
  |> Enum.map(&[&1, {:"sha#{&1}", :"sha3_#{&1}", :"keccak_#{&1}", :"blake2b_#{&1}"}])
  |> Enum.each(fn [bits, {sha2_func, sha3_func, keccak_func, blake2b_func}] ->
    bytes = div(bits, 8)

    def unquote(sha2_func)(data), do: :crypto.hash(unquote(sha2_func), data)
    def unquote(sha3_func)(data), do: apply(:libdecaf, unquote(sha3_func), [data])
    def unquote(keccak_func)(data), do: apply(:keccakf1600, unquote(sha3_func), [data])

    def unquote(blake2b_func)(data, key \\ "", salt \\ "", personal \\ ""),
      do: Blake2.Blake2b.hash(data, key, unquote(bytes), salt, personal)
  end)

  def md5(data), do: :crypto.hash(:md5, data)

  def ripemd160(data), do: :crypto.hash(:ripemd160, data)

  def hash160(data), do: data |> sha256() |> ripemd160()

  def double_sha256(data), do: data |> sha256() |> sha256()
end
