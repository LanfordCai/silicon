defmodule Silicon.Secp256k1 do
  @moduledoc """
  """

  @type pubkey :: binary()
  @type privkey :: binary()
  @type compression :: :compressed | :uncompressed
  @type signature :: binary()
  @type recovery_id :: integer()

  @spec key_pair() :: {pubkey(), privkey()}
  def key_pair do
    privkey = :crypto.strong_rand_bytes(32)
    {:ok, pubkey} = :libsecp256k1.ec_pubkey_create(privkey, :uncompressed)
    {pubkey, privkey}
  end

  @spec derive_pubkey(privkey(), compression()) :: {:ok, pubkey()} | {:error, term()}
  def derive_pubkey(privkey, compression)
      when is_binary(privkey) and compression in [:compressed, :uncompressed] do
    :libsecp256k1.ec_pubkey_create(privkey, compression)
  end

  @spec privkey_tweak_add(privkey(), binary()) :: {:ok, binary()} | {:error, term()}
  def privkey_tweak_add(privkey, tweak) when is_binary(privkey) and is_binary(tweak) do
    :libsecp256k1.ec_privkey_tweak_add(privkey, tweak)
  end

  @spec privkey_tweak_mul(privkey(), binary()) :: {:ok, binary()} | {:error, term()}
  def privkey_tweak_mul(privkey, tweak) when is_binary(privkey) and is_binary(tweak) do
    :libsecp256k1.ec_privkey_tweak_mul(privkey, tweak)
  end

  @spec pubkey_tweak_add(pubkey(), binary()) :: {:ok, binary()} | {:error, term()}
  def pubkey_tweak_add(pubkey, tweak) when is_binary(pubkey) and is_binary(tweak) do
    :libsecp256k1.ec_pubkey_tweak_add(pubkey, tweak)
  end

  @spec pubkey_tweak_mul(pubkey(), binary()) :: {:ok, binary()} | {:error, term()}
  def pubkey_tweak_mul(pubkey, tweak) when is_binary(pubkey) and is_binary(tweak) do
    :libsecp256k1.ec_pubkey_tweak_mul(pubkey, tweak)
  end

  @spec sign(binary(), privkey()) :: {:ok, signature()} | {:error, term()}
  def sign(data, privkey) do
    :libsecp256k1.ecdsa_sign(data, privkey, :default, <<>>)
  end

  @spec sign_compact(binary(), privkey()) :: {:ok, signature(), recovery_id()} | {:error, term()}
  def sign_compact(data, privkey) do
    :libsecp256k1.ecdsa_sign_compact(data, privkey, :nonce_function_rfc6979, <<>>)
  end

  @spec compress_pubkey(uncompressed_pubkey :: pubkey()) :: {:ok, pubkey()} | {:error, term()}
  def compress_pubkey(<<4::8, x::256, y::256>>) when rem(y, 2) == 0,
    do: {:ok, <<2::8, x::256>>}

  def compress_pubkey(<<4::8, x::256, y::256>>) when rem(y, 2) == 1,
    do: {:ok, <<3::8, x::256>>}

  def compress_pubkey(_), do: {:error, :invalid_pubkey}

  @spec decompress_pubkey(compressed_pubkey :: pubkey()) :: {:ok, pubkey()} | {:error, term()}
  def decompress_pubkey(<<prefix::8, _rest::binary>> = pubkey) when prefix in [2, 3] do
    :libsecp256k1.ec_pubkey_decompress(pubkey)
  end

  @spec verify(binary(), signature(), pubkey()) :: :ok | :error | {:error, term()}
  def verify(data, signature, pubkey) do
    :libsecp256k1.ecdsa_verify(data, signature, pubkey)
  end

  @spec verify_compact(binary(), signature(), pubkey()) :: :ok | :error | {:error, term()}
  def verify_compact(data, signature, pubkey) do
    :libsecp256k1.ecdsa_verify_compact(data, signature, pubkey)
  end

  @spec recover_compact(binary(), signature(), recovery_id(), compression()) ::
          {:ok, pubkey()} | {:error, term()}
  def recover_compact(data, signature, recovery_id, compression)
      when compression in [:compressed, :uncompressed] do
    :libsecp256k1.ecdsa_recover_compact(data, signature, compression, recovery_id)
  end
end
