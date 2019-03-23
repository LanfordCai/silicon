defmodule Silicon.Secp256k1 do
  @spec key_pair() :: {pubkey :: binary(), privkey :: binary()}
  def key_pair do
    privkey = :crypto.strong_rand_bytes(32)
    pubkey = :libsecp256k1.ec_pubkey_create(privkey, :uncompressed)
    {pubkey, privkey}
  end

  @spec derive_pubkey(privkey :: binary(), type :: :compressed | :uncompressed) :: binary()
  def derive_pubkey(privkey, type)
      when is_binary(privkey) and type in [:compressed, :uncompressed] do
    {:ok, pubkey} = :libsecp256k1.ec_pubkey_create(privkey, type)
    pubkey
  end

  def pubkey_tweak_add(pubkey, tweak) when is_binary(pubkey) and is_binary(tweak) do
    {:ok, result} = :libsecp256k1.ec_pubkey_tweak_add(pubkey, tweak)
    result
  end

  def pubkey_tweak_mult(pubkey, tweak) when is_binary(pubkey) and is_binary(tweak) do
    {:ok, result} = :libsecp256k1.ec_pubkey_tweak_mul(pubkey, tweak)
    result
  end

  def sign(data, privkey) do
    {:ok, signature} = :libsecp256k1.ecdsa_sign(data, privkey, :default, <<>>)
    signature
  end

  def sign_compact(data, privkey) do
    {:ok, <<r::256, s::256>>, recovery_id} =
      :libsecp256k1.ecdsa_sign_compact(data, privkey, :nonce_function_rfc6979, <<>>)

    {r, s, recovery_id}
  end

  def compress_pubkey(<<4::8, x::256, y::256>>) when rem(y, 2) == 0,
    do: <<2::8, x::256>>

  def compress_pubkey(<<4::8, x::256, y::256>>) when rem(y, 2) == 1,
    do: <<3::8, x::256>>

  def decompress_pubkey(<<prefix::8, _rest::binary>> = pubkey) when prefix in [2, 3] do
    {:ok, pubkey} = :libsecp256k1.ec_pubkey_decompress(pubkey)
    pubkey
  end

  def verify(data, signature, pubkey) do
    :libsecp256k1.ecdsa_verify(data, signature, pubkey)
  end

  def verify_compact(data, signature, pubkey) do
    :libsecp256k1.ecdsa_verify_compact(data, signature, pubkey)
  end

  def recover_compact(data, signature, recovery_id, compression)
      when compression in [:compressed, :uncompressed] do
    :libsecp256k1.ecdsa_recover_compact(data, signature, compression, recovery_id)
  end
end
