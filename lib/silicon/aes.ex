defmodule Silicon.AES do
  @moduledoc """
  Implemented AES-CBC, AES-CBC-PKCS7, AES-CTR, AES-GCM
  """

  defmodule CBC do
    @moduledoc """
    """

    @type padding :: :pkcs7 | :none

    alias Silicon.Padding.PKCS7
    @block_size 16

    @spec encrypt(binary(), binary(), binary(), padding()) :: [iv: binary(), ciphertext: binary()]
    def encrypt(key, plaintext, iv, padding \\ :pkcs7)
        when byte_size(key) in [16, 24, 32] and byte_size(iv) == 16 and padding in [:pkcs7, :none] do
      plaintext =
        case padding do
          :pkcs7 -> PKCS7.pad(plaintext, @block_size)
          :none -> plaintext
        end

      ciphertext = :crypto.block_encrypt(:aes_cbc, key, iv, plaintext)
      [iv: iv, ciphertext: ciphertext]
    end

    @spec decrypt(binary(), binary(), binary(), padding()) :: binary()
    def decrypt(key, ciphertext, iv, padding \\ :pkcs7)
        when byte_size(key) in [16, 24, 32] and byte_size(iv) == 16 and padding in [:pkcs7, :none] do
      plaintext = :crypto.block_decrypt(:aes_cbc, key, iv, ciphertext)

      case padding do
        :pkcs7 -> PKCS7.unpad(plaintext)
        :none -> plaintext
      end
    end
  end

  defmodule GCM do
    @moduledoc """
    """

    @spec encrypt(binary(), binary(), binary(), binary(), integer()) :: [
            iv: binary(),
            ciphertext: binary(),
            tag: binary()
          ]
    def encrypt(key, plaintext, iv, aad, tag_length)
        when byte_size(key) in [16, 24, 32] and byte_size(iv) >= 1 and tag_length in 1..16 do
      {ciphertext, tag} = :crypto.block_encrypt(:aes_gcm, key, iv, {aad, plaintext, tag_length})
      [iv: iv, ciphertext: ciphertext, tag: tag]
    end

    @spec decrypt(binary(), binary(), binary(), binary(), binary()) :: binary()
    def decrypt(key, ciphertext, iv, aad, tag)
        when byte_size(key) in [16, 24, 32] and byte_size(iv) >= 1 and
               byte_size(tag) in 1..16 do
      :crypto.block_decrypt(:aes_gcm, key, iv, {aad, ciphertext, tag})
    end
  end

  defmodule CTR do
    @moduledoc """
    """

    @spec encrypt(binary(), binary(), binary()) :: [iv: binary(), ciphertext: binary()]
    def encrypt(key, plaintext, iv)
        when byte_size(key) in [16, 24, 32] and byte_size(iv) == 16 do
      {_new_state, ciphertext} =
        :aes_ctr
        |> :crypto.stream_init(key, iv)
        |> :crypto.stream_encrypt(plaintext)

      [iv: iv, ciphertext: ciphertext]
    end

    @spec decrypt(binary(), binary(), binary()) :: binary()
    def decrypt(key, ciphertext, iv)
        when byte_size(key) in [16, 24, 32] and byte_size(iv) == 16 do
      {_new_state, plaintext} =
        :aes_ctr
        |> :crypto.stream_init(key, iv)
        |> :crypto.stream_decrypt(ciphertext)

      plaintext
    end
  end
end
