defmodule Silicon.HashTest do
  use ExUnit.Case
  import Silicon.DataCase.Hash
  import Silicon.Hash

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
      do_test(:blake2b, :blake2b_224, &blake2b_224/4)
    end

    test "blake2b_256" do
      do_test(:blake2b, :blake2b_256, &blake2b_256/4)
    end

    test "blake2b_384" do
      do_test(:blake2b, :blake2b_384, &blake2b_384/4)
    end

    test "blake2b_512" do
      do_test(:blake2b, :blake2b_512, &blake2b_512/4)
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

    digest = Base.encode16(func.(msg, key, salt, pers), case: :lower)
    expected_digest = String.downcase(out)

    {digest, expected_digest}
  end
end
