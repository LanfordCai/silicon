defmodule Silicon.AESTest do
  @moduledoc """
  The test vectors of AES are from:
  1. AES-CBC: 
    https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES
  2. AES-CBC-PKCS7:
    https://raw.githubusercontent.com/google/wycheproof/master/testvectors/aes_cbc_pkcs5_test.json
  3. AES-GCM:
    https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS
  4. AES-CTR:
    Got from https://github.com/pyca/cryptography, which is the test vectors from RFC 3686
  """

  use ExUnit.Case
  import Silicon.DataCase.AES

  alias Silicon.AES

  test "aes_cbc" do
    Enum.each(aes_cbc_test_vectors(), &do_cbc_test(&1))
  end

  test "aes_cbc_pkcs7" do
    Enum.each(aes_cbc_pkcs7_test_vectors(), &do_cbc_pkcs7_test(&1))
  end

  test "aes_gcm" do
    Enum.each(aes_gcm_test_vectors(), &do_gcm_test(&1))
  end

  test "aes_ctr" do
    Enum.each(aes_ctr_test_vectors(), &do_ctr_test(&1))
  end

  defp do_cbc_test(%{key: key, iv: iv, ciphertext: ct, plaintext: pt} = vector) do
    [key, iv, ct, pt] = [key, iv, ct, pt] |> Enum.map(&Base.decode16!(&1, case: :mixed))
    [iv: _iv, ciphertext: ciphertext] = AES.CBC.encrypt(key, pt, iv, :none)
    plaintext = AES.CBC.decrypt(key, ct, iv, :none)

    assert ciphertext == ct,
           "failed encrypt in #{inspect(vector)}. expect: #{ct}, got: #{ciphertext}"

    assert plaintext == pt,
           "failed decrypt in #{inspect(vector)}, expect: #{pt}, got: #{plaintext}"
  end

  defp do_cbc_pkcs7_test(
         %{"ct" => ct, "iv" => iv, "key" => key, "msg" => msg, "result" => result} = vector
       ) do
    [iv, key, msg, ct] = [iv, key, msg, ct] |> Enum.map(&Base.decode16!(&1, case: :lower))
    [iv: _, ciphertext: ciphertext] = AES.CBC.encrypt(key, msg, iv)
    plaintext = AES.CBC.decrypt(key, ct, iv)

    case result do
      "invalid" ->
        assert ciphertext != ct, "failed encrypt in #{inspect(vector)}"

        assert plaintext == {:error, :invalid_padding} or plaintext != msg,
               "failed decrypt in #{inspect(vector)}"

      "valid" ->
        assert ciphertext == ct, "failed encrypt in #{inspect(vector)}"
        assert plaintext == msg, "failed decrypt in #{inspect(vector)}"
    end
  end

  defp do_gcm_test(
         %{key: key, iv: iv, ciphertext: ct, plaintext: pt, aad: aad, tag: tag} = vector
       ) do
    [key, iv, ct, pt, tag, aad] =
      [key, iv, ct, pt, tag, aad]
      |> Enum.map(&Base.decode16!(&1, case: :mixed))

    [iv: _iv, ciphertext: ciphertext, tag: ciphertag] =
      AES.GCM.encrypt(key, pt, iv, aad, byte_size(tag))

    assert ciphertext == ct,
           "aes_gcm: encryption failed! vector: #{inspect(vector)}"

    assert ciphertag == tag,
           "aes_gcm: encryption failed! vector: #{inspect(vector)}"

    plaintext = AES.GCM.decrypt(key, ct, iv, aad, tag)

    assert plaintext == pt,
           "aes_gcm: decryption failed! vector: #{inspect(vector)}"
  end

  defp do_gcm_test(%{key: key, iv: iv, ciphertext: ct, fail: _, aad: aad, tag: tag}) do
    [key, iv, ct, tag, aad] =
      [key, iv, ct, tag, aad]
      |> Enum.map(&Base.decode16!(&1, case: :mixed))

    assert AES.GCM.decrypt(key, ct, iv, aad, tag) == :error
  end

  def do_ctr_test(%{key: key, iv: iv, ciphertext: ct, plaintext: pt} = vector) do
    [key, iv, ct, pt] =
      [key, iv, ct, pt]
      |> Enum.map(&Base.decode16!(&1))

    [iv: _iv, ciphertext: ciphertext] = AES.CTR.encrypt(key, pt, iv)

    assert ciphertext == ct,
           "aes_ctr: failed encrypt in #{inspect(vector)}. expect: #{ct}, got: #{ciphertext}"

    plaintext = AES.CTR.decrypt(key, ct, iv)

    assert plaintext == pt,
           "aes_ctr: failed decrypt in #{inspect(vector)}, expect: #{pt}, got: #{plaintext}"
  end
end
