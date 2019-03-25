defmodule Silicon.Ed25519 do
  @moduledoc """
  """

  @type public_key :: binary()
  @type secret :: binary()
  @type secret_key :: binary()
  @type signature :: binary()

  @spec key_pair() :: {public_key(), secret_key()}
  def key_pair do
    :libdecaf_curve25519.eddsa_keypair()
  end

  @spec secret_to_public_key(secret()) :: {:ok, public_key()} | :error
  def secret_to_public_key(secret) do
    {:ok, :libdecaf_curve25519.eddsa_secret_to_pk(secret)}
  rescue
    _ -> :error
  end

  @spec secret_key_to_public_key(secret_key()) :: {:ok, public_key()} | :error
  def secret_key_to_public_key(secret_key) do
    {:ok, :libdecaf_curve25519.eddsa_sk_to_pk(secret_key)}
  rescue
    _ -> :error
  end

  @spec secret_key_to_secret(secret_key()) :: {:ok, secret()} | :error
  def secret_key_to_secret(secret_key) do
    {:ok, :libdecaf_curve25519.eddsa_sk_to_secret(secret_key)}
  rescue
    _ -> :error
  end

  @spec sign(binary(), secret_key()) :: {:ok, signature()} | :error
  def sign(data, secret_key) do
    {:ok, :libdecaf_curve25519.ed25519_sign(data, secret_key)}
  rescue
    _ -> :error
  end

  @spec verify(binary(), binary, public_key()) :: :ok | :error
  def verify(signature, data, public_key) do
    case :libdecaf_curve25519.ed25519_verify(signature, data, public_key) do
      true -> :ok
      _ -> :error
    end
  end
end
