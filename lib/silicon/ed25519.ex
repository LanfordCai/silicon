defmodule Silicon.Ed25519 do
  @moduledoc false

  @secret_bytes 32
  @public_key_bytes 32
  @secret_key_bytes 64

  defguardp is_secret(secret) when byte_size(secret) == @secret_bytes
  defguardp is_secret_key(secret_key) when byte_size(secret_key) == @secret_key_bytes
  defguardp is_public_key(public_key) when byte_size(public_key) == @public_key_bytes

  def key_pair do
    :libdecaf_curve25519.eddsa_keypair()
  end

  def secret_to_public_key(secret) when is_secret(secret) do
    :libdecaf_curve25519.eddsa_secret_to_pk(secret)
  end

  def secret_key_to_public_key(secret_key) when is_secret_key(secret_key) do
    :libdecaf_curve25519.eddsa_sk_to_pk(secret_key)
  end

  def secret_key_to_secret(secret_key) when is_secret_key(secret_key) do
    :libdecaf_curve25519.eddsa_sk_to_secret(secret_key)
  end

  def sign(data, secret_key) when is_secret_key(secret_key) do
    :libdecaf_curve25519.ed25519_sign(data, secret_key)
  end

  def verify(signature, data, public_key) when is_public_key(public_key) do
    :libdecaf_curve25519.ed25519_verify(signature, data, public_key)
  end
end
