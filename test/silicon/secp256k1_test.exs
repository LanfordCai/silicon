defmodule Silicon.Secp256k1Test do
  @moduledoc """
  test vectors are from:
  1. https://github.com/btccom/secp256k1-go
  2. https://github.com/google/wycheproof/tree/master/testvectors
  """

  use ExUnit.Case
  import Silicon.DataCase.Secp256k1
  import Silicon.{Hash, Secp256k1}

  test "key_pair" do
    1..1000
    |> Enum.map(fn _ -> key_pair() end)
    |> Enum.each(fn {pubkey, privkey} ->
      assert byte_size(privkey) == 32
      assert derive_pubkey(privkey, :uncompressed) == pubkey
    end)
  end

  test "verify" do
    sign_vectors()
    |> Enum.each(fn %{"msg" => msg, "privkey" => privkey, "sig" => sig} ->
      msg = Base.decode16!(msg, case: :lower)
      sig = Base.decode16!(String.replace_suffix(sig, "01", ""), case: :lower)
      privkey = Base.decode16!(privkey, case: :lower)
      pubkey = derive_pubkey(privkey, :uncompressed)
      assert verify(msg, sig, pubkey) == :ok
    end)
  end

  test "sign" do
    sign_vectors()
    |> Enum.each(fn %{"msg" => msg, "privkey" => privkey, "sig" => sig} ->
      msg = Base.decode16!(msg, case: :lower)
      privkey = Base.decode16!(privkey, case: :lower)
      sig = String.replace_suffix(sig, "01", "")

      assert Base.encode16(sign(msg, privkey), case: :lower) == sig
    end)
  end

  test "derive_pubkey" do
    pubkey_vectors()
    |> Enum.each(fn %{"seckey" => privkey, "compressed" => cpubkey, "pubkey" => pubkey} ->
      privkey = Base.decode16!(privkey, case: :lower)

      uncompressed_pubkey =
        privkey
        |> derive_pubkey(:uncompressed)
        |> Base.encode16(case: :lower)

      assert uncompressed_pubkey == pubkey

      compressed_pubkey =
        privkey
        |> derive_pubkey(:compressed)
        |> Base.encode16(case: :lower)

      assert compressed_pubkey == cpubkey
    end)
  end

  test "compress_pubkey and decompress_pubkey" do
    pubkey_vectors()
    |> Enum.each(fn %{"compressed" => cpubkey, "pubkey" => pubkey} ->
      cpubkey = Base.decode16!(cpubkey, case: :lower)
      pubkey = Base.decode16!(pubkey, case: :lower)
      assert compress_pubkey(pubkey) == cpubkey
      assert decompress_pubkey(cpubkey) == pubkey
    end)
  end

  test "pubkey_tweak_add" do
    pubkey_tweak_add_vectors()
    |> Enum.each(fn %{"publicKey" => pubkey, "tweak" => tweak, "tweaked" => tweaked} ->
      [pubkey, tweak, tweaked] =
        Enum.map([pubkey, tweak, tweaked], &Base.decode16!(&1, case: :lower))

      pubkey_tweak_add(pubkey, tweak) == tweaked
    end)
  end

  test "pubkey_tweak_mul" do
    pubkey_tweak_mul_vectors()
    |> Enum.each(fn %{"publicKey" => pubkey, "tweak" => tweak, "tweaked" => tweaked} ->
      [pubkey, tweak, tweaked] =
        Enum.map([pubkey, tweak, tweaked], &Base.decode16!(&1, case: :lower))

      pubkey_tweak_mul(pubkey, tweak) == tweaked
    end)
  end

  test "privkey_tweak_add" do
    privkey_tweak_add_vectors()
    |> Enum.each(fn %{"privkey" => privkey, "tweak" => tweak, "tweaked" => tweaked} ->
      [privkey, tweak, tweaked] =
        Enum.map([privkey, tweak, tweaked], &Base.decode16!(&1, case: :lower))

      privkey_tweak_add(privkey, tweak) == tweaked
    end)
  end

  test "privkey_tweak_mul" do
    privkey_tweak_mul_vectors()
    |> Enum.each(fn %{"privkey" => privkey, "tweak" => tweak, "tweaked" => tweaked} ->
      [privkey, tweak, tweaked] =
        Enum.map([privkey, tweak, tweaked], &Base.decode16!(&1, case: :lower))

      privkey_tweak_mul(privkey, tweak) == tweaked
    end)
  end

  test "sign_compact/verify_compact/recover_compact" do
    Enum.each(1..1000, fn _ ->
      {pubkey, privkey} = key_pair()
      data = :crypto.strong_rand_bytes(32)
      {r, s, recovery_id} = sign_compact(data, privkey)
  
      assert verify_compact(data, r <> s, pubkey) == :ok
      assert recover_compact(data, r <> s, recovery_id, :uncompressed) == {:ok, pubkey}

      compressed_pubkey = compress_pubkey(pubkey)
      assert recover_compact(data, r <> s, recovery_id, :compressed) == {:ok, compressed_pubkey}
    end)
  end

  test "wycheproof_ecdh" do
    Enum.each(wycheproof_ecdh_vectors(), &do_ecdh_test(&1))
  end

  # test "wycheproof_ecdsa" do
  #   wycheproof_ecdsa_vectors()
  #   |> Enum.each(fn %{"key" => key, "tests" => tests} ->
  #     pubkey = Base.decode16!(key["uncompressed"], case: :lower)
  #     tests
  #     |> Enum.each(fn %{"tcId" => id, "msg" => msg, "sig" => sig, "result" => result, "comment" => comment} ->
  #       msg = sha256(Base.decode16!(msg, case: :lower))
  #       sig = Base.decode16!(sig, case: :lower)
  #       verify_result = verify(msg, sig, pubkey)
  #       if result == "valid" and comment != "signature malleability" do
  #         assert verify_result == :ok, "Failed on vector #{id}, Expect :ok, got #{inspect(verify_result)}" 
  #       else
  #         refute verify_result == :ok, "Failed on vector #{id}. Expect error, got #{inspect(verify_result)}" 
  #       end
  #     end)
  #   end)
  # end

  defp do_ecdh_test(%{
         "result" => result,
         "public" => public,
         "private" => private,
         "shared" => shared
       }) do
    public = Base.decode16!(public, case: :lower)

    privkey = Base.decode16!(private, case: :lower)

    {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, _, _}, pubkey} =
      :public_key.der_decode(:SubjectPublicKeyInfo, public)

    <<_::8, shared_secret::binary>> =
      pubkey
      |> pubkey_tweak_mul(privkey)
      |> compress_pubkey()

    assert result in ["valid", "acceptable"] and
             Base.encode16(shared_secret, case: :lower) == shared
  rescue
    _error ->
      assert result == "invalid"
  end
end
