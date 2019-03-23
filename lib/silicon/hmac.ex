defmodule Silicon.Hmac do
  # Hmac with sha2 hash function
  [256, 512]
  |> Enum.map(&{:"hmac_sha#{&1}", :"sha#{&1}"})
  |> Enum.each(fn {func, sha} ->
    def unquote(func)(key, data), do: :crypto.hmac(unquote(sha), key, data)
  end)
end
