defmodule Silicon.DataCase.Secp256k1 do
  @moduledoc false

  @vectors_path "test/test_vectors/secp256k1"

  def sign_vectors do
    "#{@vectors_path}/secp256k1-go/sign_vectors.yaml"
    |> YamlElixir.read_from_file!()
  end

  def pubkey_vectors do
    "#{@vectors_path}/secp256k1-go/pubkey_vectors.yaml"
    |> YamlElixir.read_from_file!()
  end

  def pubkey_tweak_add_vectors do
    "#{@vectors_path}/secp256k1-go/pubkey_tweak_add_vectors.yaml"
    |> YamlElixir.read_from_file!()
  end

  def pubkey_tweak_mul_vectors do
    "#{@vectors_path}/secp256k1-go/pubkey_tweak_mul_vectors.yaml"
    |> YamlElixir.read_from_file!()
  end

  def privkey_tweak_add_vectors do
    "#{@vectors_path}/secp256k1-go/privkey_tweak_add_vectors.yaml"
    |> YamlElixir.read_from_file!()
  end

  def privkey_tweak_mul_vectors do
    "#{@vectors_path}/secp256k1-go/privkey_tweak_mul_vectors.yaml"
    |> YamlElixir.read_from_file!()
  end

  def wycheproof_ecdh_vectors do
    "#{@vectors_path}/ecdh_secp256k1_test.json"
    |> File.read!()
    |> Poison.decode!()
    |> Map.get("testGroups")
    |> Enum.filter(&(&1["curve"] == "secp256k1"))
    |> Enum.flat_map(& &1["tests"])
    |> Enum.reject(fn %{"private" => private} ->
      # reject odd-length private_key
      Base.decode16(private, case: :lower) == :error
    end)
  end

end
