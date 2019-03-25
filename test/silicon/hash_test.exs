defmodule Silicon.HashTest do
  @moduledoc """
  test vectors are from:
  1. SHA3:
    https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing
  2. Keccak origin:
    https://keccak.team/archives.html Known-answer and Monte Carlo test results part
  3. Blake2b:
    https://github.com/jedisct1/crypto-test-vectors
    https://pynacl.readthedocs.io/en/latest/vectors/blake2_vectors/
  4. MD5/SHA2
    https://cryptii.com
  5. HASH160
    https://bitcoinprices.org/public-key-to-hash/
  6. RIPEMD160
    https://www.browserling.com/tools/ripemd160-hash
  """

  use ExUnit.Case
  import Silicon.DataCase.Hash
  import Silicon.Hash

  test "md5" do
    msg = ""
    assert Base.encode16(md5(msg), case: :lower) == "d41d8cd98f00b204e9800998ecf8427e"

    msg = "The quick brown fox jumps over the lazy dog"
    assert Base.encode16(md5(msg), case: :lower) == "9e107d9d372bb6826bd81d3542a419d6"

    msg = "How many roads must a man walk down, before you call him a man?"
    assert Base.encode16(md5(msg), case: :lower) == "e1ec4d8baf10c73743cc418a9a9e1539"
  end

  test "ripemd160" do
    msg = ""

    assert Base.encode16(ripemd160(msg), case: :lower) ==
             "9c1185a5c5e9fc54612808977ee8f548b2258d31"

    msg = "The quick brown fox jumps over the lazy dog"

    assert Base.encode16(ripemd160(msg), case: :lower) ==
             "37f332f68db77bd9d7edd4969571ad671cf9dd3b"

    msg = "How many roads must a man walk down, before you call him a man?"

    assert Base.encode16(ripemd160(msg), case: :lower) ==
             "29bc5475c75121026a9799957f552710815076bd"
  end

  test "hash160" do
    msg =
      "04f7f8fd63c20fed2fc1491eb3a502727e40e6a7fd806ea307ea44d2cc0d95ea32b137011ec19f04f5e571882e444da7af5011bc6f8b83b79a2239a7cdfe371ea9"

    assert Base.encode16(hash160(Base.decode16!(msg, case: :lower)), case: :lower) ==
             "005584b10c9a687a993debab084a0a0d9c80b98b"

    msg =
      "04f8ea155a428f9bb6569c6e17e25d95680ff104e16ad5ea43c6fbe7b17909c1d7c36ab6712dd319cc2f1531b91d8e0baaf40a119d8a02522ba2ff732e8dc2ad0d"

    assert Base.encode16(hash160(Base.decode16!(msg, case: :lower)), case: :lower) ==
             "b6612bb3bb9d629456a434078897c5ee514ba437"

    msg =
      "04cb22eae9222c19b984f4ffdd7be855203d7045f61fe83d2e688872177de00da546280c6bd93d80a6b2d78f1c5d96efdf32fecb360bc3329452f7735b87018118"

    assert Base.encode16(hash160(Base.decode16!(msg, case: :lower)), case: :lower) ==
             "0e8b29f6aa141c194fe0d280a15c03456a65a045"
  end

  test "double_sha256" do
    msg = "hello"

    assert Base.encode16(double_sha256(msg), case: :lower) ==
             "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
  end

  describe "sha2 test" do
    test "sha224" do
      msg = ""

      assert Base.encode16(sha224(msg), case: :lower) ==
               "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"

      msg = "The quick brown fox jumps over the lazy dog"

      assert Base.encode16(sha224(msg), case: :lower) ==
               "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"

      msg = "How many roads must a man walk down, before you call him a man?"

      assert Base.encode16(sha224(msg), case: :lower) ==
               "8e744b0940f4dad0ca6d79fe33f8ebf8fb7e1a52d5ca7d13f06e045b"
    end

    test "sha256" do
      msg = ""

      assert Base.encode16(sha256(msg), case: :lower) ==
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

      msg = "The quick brown fox jumps over the lazy dog"

      assert Base.encode16(sha256(msg), case: :lower) ==
               "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"

      msg = "How many roads must a man walk down, before you call him a man?"

      assert Base.encode16(sha256(msg), case: :lower) ==
               "560cbc3c0c6912e673bbf7e7061f94fee5e624097bacda3759e2eaf5a391ef5a"
    end

    test "sha384" do
      msg = ""

      assert Base.encode16(sha384(msg), case: :lower) ==
               "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"

      msg = "The quick brown fox jumps over the lazy dog"

      assert Base.encode16(sha384(msg), case: :lower) ==
               "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"

      msg = "How many roads must a man walk down, before you call him a man?"

      assert Base.encode16(sha384(msg), case: :lower) ==
               "f8dce6b237f31d4e3a70083a74ccb9aead9987063daa99e3e7d199ddebd523a5655e3631ca75242b3c71dfb3464af67c"
    end

    test "sha512" do
      msg = ""

      assert Base.encode16(sha512(msg), case: :lower) ==
               "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

      msg = "The quick brown fox jumps over the lazy dog"

      assert Base.encode16(sha512(msg), case: :lower) ==
               "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"

      msg = "How many roads must a man walk down, before you call him a man?"

      assert Base.encode16(sha512(msg), case: :lower) ==
               "601a0a553a3ef2b36572d89ac43c44dd3fe0f0b543bf31de4f2c9272a568cb998807d7b7f1f6bc5c6fa622cf531999b3d9d2609a49a335e17f847f1843dbd528"
    end
  end

  describe "sha3 test" do
    test "sha3_224" do
      do_test(:sha3, :sha3_224, &sha3_224/1)
    end

    test "sha3_256" do
      do_test(:sha3, :sha3_256, &sha3_256/1)
    end

    test "sha3_384" do
      do_test(:sha3, :sha3_384, &sha3_384/1)
    end

    test "sha3_512" do
      do_test(:sha3, :sha3_512, &sha3_512/1)
    end
  end

  describe "keccak test" do
    test "keccak_224" do
      do_test(:keccak, :keccak_224, &keccak_224/1)
    end

    test "keccak_256" do
      do_test(:keccak, :keccak_256, &keccak_256/1)
    end

    test "keccak_384" do
      do_test(:keccak, :keccak_384, &keccak_384/1)
    end

    test "keccak_512" do
      do_test(:keccak, :keccak_512, &keccak_512/1)
    end
  end

  describe "blake2b test" do
    test "blake2b_224" do
      do_test(:blake2b, :blake2b_224, &blake2b_224/3)
    end

    test "blake2b_256" do
      do_test(:blake2b, :blake2b_256, &blake2b_256/3)
    end

    test "blake2b_384" do
      do_test(:blake2b, :blake2b_384, &blake2b_384/3)
    end

    test "blake2b_512" do
      do_test(:blake2b, :blake2b_512, &blake2b_512/3)
    end
  end

  def do_test(algo, name, func) do
    test_vectors(name)
    |> Enum.each(fn vector ->
      {digest, expected_digest} = digest(algo, vector, func)

      assert digest == String.downcase(expected_digest),
             "#{name} vector = #{inspect(vector)}, digest = #{digest}, expected_digest = #{
               expected_digest
             }"
    end)
  end

  defp digest(algo, %{msg: msg, md: md}, func) when algo in [:sha3, :keccak] do
    digest =
      msg
      |> Base.decode16!(case: :mixed)
      |> func.()
      |> Base.encode16(case: :lower)

    expected_digest = String.downcase(md)
    {digest, expected_digest}
  end

  defp digest(:blake2b, %{msg: msg, key: key, out: out, salt: salt, pers: pers}, func) do
    [msg, key, salt, pers] =
      [msg, key, salt, pers]
      |> Enum.map(&Base.decode16!(&1, case: :lower))

    digest = Base.encode16(func.(msg, key, salt: salt, personal: pers), case: :lower)
    expected_digest = String.downcase(out)

    {digest, expected_digest}
  end
end
