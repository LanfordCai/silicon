defmodule Silicon.DataCase.AES do
  @moduledoc """
  The test vectors of AES are from:
  1. ciphers without PKCS7 padding
  https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES
  https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS

  2. ciphers with PKCS7 padding
  https://raw.githubusercontent.com/google/wycheproof/master/testvectors/aes_cbc_pkcs5_test.json
  https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
  """
  @vectors_path "test/test_vectors/aes"

  def aes_cbc_test_vectors do
    path = "#{@vectors_path}/cbc"
    keywords = ["COUNT", "KEY", "IV", "PLAINTEXT", "CIPHERTEXT"]

    path
    |> File.ls!()
    |> Enum.map(&Path.join([path, &1]))
    |> Enum.flat_map(&prepare_aes_test_vectors(:cbc, &1, keywords))
  end

  def aes_cbc_pkcs7_test_vectors do
    "#{@vectors_path}/cbc_pkcs7/aes_cbc_pkcs7_test.json"
    |> prepare_aes_cbc_pkcs7_test_vectors()
  end

  def aes_ecb_test_vectors do
    path = "#{@vectors_path}/ecb"
    keywords = ["COUNT", "KEY", "PLAINTEXT", "CIPHERTEXT"]

    path
    |> File.ls!()
    |> Enum.map(&Path.join([path, &1]))
    |> Enum.flat_map(&prepare_aes_test_vectors(:ecb, &1, keywords))
  end

  def aes_gcm_test_vectors do
    path = "#{@vectors_path}/gcm"
    keywords = ["Count", "Key", "IV", "PT", "AAD", "CT", "Tag"]

    path
    |> File.ls!()
    |> Enum.map(&Path.join([path, &1]))
    |> Enum.flat_map(&prepare_aes_test_vectors(:gcm, &1, keywords))
  end

  def aes_ctr_test_vectors do
    path = "#{@vectors_path}/ctr"
    keywords = ["COUNT", "KEY", "PLAINTEXT", "CIPHERTEXT", "IV"]

    path
    |> File.ls!()
    |> Enum.map(&Path.join([path, &1]))
    |> Enum.flat_map(&prepare_aes_test_vectors(:ctr, &1, keywords))
  end

  defp prepare_aes_test_vectors(mode, path, keywords) do
    prefixes = Enum.map(keywords, &(&1 <> " ="))
    chunk_size = Enum.count(prefixes)
    prefixes = ["FAIL" | prefixes]

    path
    |> File.stream!()
    |> Stream.map(&String.trim/1)
    |> Stream.filter(fn str ->
      Enum.any?(prefixes, &String.starts_with?(str, &1))
    end)
    |> Stream.chunk_every(chunk_size)
    |> (fn stream ->
          case mode do
            :gcm -> Stream.take_every(stream, 50)
            _ -> stream
          end
        end).()
    |> Stream.map(&vector_to_map(&1, prefixes))
    |> Enum.to_list()
  end

  defp prepare_aes_cbc_pkcs7_test_vectors(path) do
    path
    |> File.read!()
    |> Poison.decode!()
    |> Map.get("testGroups")
    |> Enum.flat_map(& &1["tests"])
  end

  defp key_with_prefix(prefix)
       when prefix in [
              "Count",
              "Key",
              "Tag",
              "COUNT",
              "KEY",
              "IV",
              "PLAINTEXT",
              "CIPHERTEXT",
              "AAD",
              "TAG",
              "FAIL"
            ] do
    :"#{String.downcase(prefix)}"
  end

  defp key_with_prefix("PT"), do: :plaintext
  defp key_with_prefix("CT"), do: :ciphertext

  defp vector_to_map(vector, prefixes) when is_list(vector) do
    Enum.reduce(vector, %{}, fn row, acc ->
      prefix = Enum.find(prefixes, &String.starts_with?(row, &1))
      key = key_with_prefix(String.replace_suffix(prefix, " =", ""))
      content = row |> String.replace_prefix(prefix, "") |> String.trim()
      Map.put(acc, key, content)
    end)
  end
end
