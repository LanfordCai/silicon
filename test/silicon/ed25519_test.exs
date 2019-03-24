defmodule Silicon.Ed25519Test do
  @moduledoc """
  test vectors are from:
  1. https://ed25519.cr.yp.to/python/sign.input
  """
  
  use ExUnit.Case
  import Silicon.Ed25519

  @vectors_path "test/test_vectors/ed25519"

  @vectors "#{@vectors_path}/sign.input"
            |> File.stream!()
            |> Stream.map(fn line ->
              [sk, pk, m, sm, _] = String.split(String.trim(line), ":")
              [sk, pk, m, sm]
              |> Enum.map(& Base.decode16!(&1, case: :lower))
            end)
            |> Enum.to_list()

  test "key_pair" do
    1..1000
    |> Enum.each(fn _ ->
      {pubkey, secret_key} = key_pair()
      assert secret_key_to_public_key(secret_key) == pubkey
    end)
  end

  test "secret_to_public_key/1" do
    @vectors
    |> Enum.each(fn [sk, pk, _msg, _sig_msg] ->
      <<secret::bytes-32, _::binary>> = sk
      assert secret_to_public_key(secret) == pk
    end)
  end

  test "secret_key_to_public_key/1" do
    @vectors
    |> Enum.each(fn [sk, pk, _msg, _sig_msg] ->
      assert secret_key_to_public_key(sk) == pk
    end)
  end

  test "secret_key_to_secret/1" do
    @vectors
    |> Enum.each(fn [sk, _pk, _msg, _sig_msg] ->
      <<secret::bytes-32, _::binary>> = sk
      assert secret_key_to_secret(sk) == secret
    end)
  end

  test "sign/2 and verify/3" do
    @vectors
    |> Enum.each(fn [sk, pk, msg, sig_msg] ->
      sig_length = byte_size(sig_msg) - byte_size(msg)
      sig = Kernel.binary_part(sig_msg, 0, sig_length)
      assert sign(msg, sk) == sig
      assert verify(sig, msg, pk)
    end) 
  end

end