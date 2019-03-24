defmodule Silicon.DataCase.Hash do
  @moduledoc false

  @vectors_path "test/test_vectors"

  [224, 256, 384, 512]
  |> Enum.each(fn size ->
    sha3_func = :"sha3_#{size}"

    def test_vectors(unquote(sha3_func)) do
      [
        "#{@vectors_path}/sha3/SHA3_#{unquote(size)}ShortMsg.txt",
        "#{@vectors_path}/sha3/SHA3_#{unquote(size)}LongMsg.txt"
      ]
      |> Enum.flat_map(&prepare_sha3_test_vectors/1)
    end

    keccak_func = :"keccak_#{size}"

    def test_vectors(unquote(keccak_func)) do
      [
        "#{@vectors_path}/keccak_orig/ShortMsgKAT_#{unquote(size)}.txt",
        "#{@vectors_path}/keccak_orig/LongMsgKAT_#{unquote(size)}.txt"
      ]
      |> Enum.flat_map(&prepare_sha3_test_vectors/1)
    end

    blake2b_func = :"blake2b_#{size}"

    def test_vectors(unquote(blake2b_func)) do
      no_salt_no_pers_vectors =
        "#{@vectors_path}/blake2b/nosalt_nopers_vectors_#{unquote(size)}"
        |> prepare_blake2b_test_vectors(:no_salt_no_pers)

      salt_pers_vectors =
        "#{@vectors_path}/blake2b/salt_pers_vectors_#{unquote(size)}"
        |> prepare_blake2b_test_vectors(:salt_pers)

      List.flatten([no_salt_no_pers_vectors, salt_pers_vectors])
    end
  end)

  defp prepare_sha3_test_vectors(path) do
    path
    |> File.stream!()
    |> Stream.map(&String.trim/1)
    |> Stream.filter(fn str ->
      ["Len", "Msg", "MD"]
      |> Enum.any?(&String.starts_with?(str, &1))
    end)
    |> Stream.chunk_every(3)
    |> Stream.reject(fn ["Len = " <> bit_len, _, _] ->
      # NOTE: We only support hash byte strings
      String.to_integer(bit_len) |> rem(8) != 0
    end)
    |> Stream.map(fn ["Len = " <> bit_len, "Msg = " <> msg, "MD = " <> digest] ->
      %{
        len: String.to_integer(bit_len),
        msg: if(msg == "00", do: "", else: msg),
        md: digest
      }
    end)
    |> Enum.to_list()
  end

  defp prepare_blake2b_test_vectors(path, :no_salt_no_pers) do
    path
    |> File.stream!()
    |> Stream.map(fn str ->
      [msg, key, _out_len, out] =
        str
        |> String.trim_trailing()
        |> String.split("\t")

      %{msg: msg, key: key, out: out, salt: "", pers: ""}
    end)
    |> Enum.to_list()
  end

  defp prepare_blake2b_test_vectors(path, :salt_pers) do
    path
    |> File.stream!()
    |> Stream.map(fn str ->
      [msg, key, salt, pers, _out_len, out] =
        str
        |> String.trim_trailing()
        |> String.split("\t")

      %{msg: msg, key: key, salt: salt, pers: pers, out: out}
    end)
    |> Enum.to_list()
  end
end
