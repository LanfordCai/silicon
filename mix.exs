defmodule Silicon.MixProject do
  use Mix.Project

  def project do
    [
      app: :silicon,
      version: "0.1.0",
      elixir: "~> 1.8",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(env) when env in [:test, :dev], do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:libdecaf, "~> 1.0"},
      {:libsecp256k1, "~> 0.1.10"},
      {:keccakf1600, "~> 2.0", hex: :keccakf1600_orig},
      {:blake2_elixir, git: "https://github.com/riverrun/blake2_elixir.git"},
      {:poison, "~> 3.1", only: [:dev, :test]}
    ]
  end
end
