defmodule Silicon.MixProject do
  use Mix.Project

  @github_url "https://github.com/LanfordCai/silicon"

  def project do
    [
      app: :silicon,
      version: "0.1.0",
      elixir: "~> 1.8",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      source_url: @github_url,
      deps: deps(),
      test_coverage: [tool: ExCoveralls]
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
      {:blake2_elixir, "~> 0.8"},
      {:poison, "~> 3.1", only: [:dev, :test]},
      {:yaml_elixir, "~> 2.1", only: [:dev, :test]},
      {:credo, "~> 1.0.0", only: [:dev, :test]},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19.0", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.10", only: [:test]}
    ]
  end

  defp description do
    """
    A wrapper of Elixir/Erlang crypto packages. Lots of extra test cases added.
    """
  end

  defp package do
    [
      licenses: ["MIT"],
      maintainers: ["lanfordcai@outlook.com"],
      links: %{
        "GitHub" => @github_url
      }
    ]
  end
end
