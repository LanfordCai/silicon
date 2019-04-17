defmodule Silicon.Hmac do
  @moduledoc """
  Hmac with SHA2 hash function
  """

  [256, 512]
  |> Enum.map(&{:"hmac_sha#{&1}", :"sha#{&1}"})
  |> Enum.each(fn {func, sha} ->
    @spec unquote(func)(binary(), binary()) :: binary()
    def unquote(func)(key, data), do: :crypto.hmac(unquote(sha), key, data)
  end)
end
