defmodule Silicon.HmacTest do
  @moduledoc """
  1. HMAC_SHA256/SHA512
    https://cryptii.com
  """

  use ExUnit.Case
  import Silicon.Hmac

  describe "hmac" do
    test "hmac sha256" do
      key = "silicon"

      msg = ""

      assert Base.encode16(hmac_sha256(key, msg), case: :lower) ==
               "5e904c41231f5879543f6846efc9b7438e5d150835256ce5fbc0eeba5f5d1d65"

      msg = "The quick brown fox jumps over the lazy dog"

      assert Base.encode16(hmac_sha256(key, msg), case: :lower) ==
               "5f6f68a9496c0c508d17ea63fa4b22ad44879f69ce0e3e40cd8c1bbbbf539055"

      msg = "How many roads must a man walk down, before you call him a man?"

      assert Base.encode16(hmac_sha256(key, msg), case: :lower) ==
               "e3178e7f4167c85e0429ca1a62a702266178281f19202048d06886a2650a4fc9"
    end

    test "hmac sha512" do
      key = "silicon"

      msg = ""

      assert Base.encode16(hmac_sha512(key, msg), case: :lower) ==
               "fdd101342d060493af38a586d6a7870523f1086b607ba4972d088141f966f89376d313cdeb2a3d4583e15db3dea331c24939449c21959fcc0b4cfed5e2ee0f99"

      msg = "The quick brown fox jumps over the lazy dog"

      assert Base.encode16(hmac_sha512(key, msg), case: :lower) ==
               "d780d28706f5f3fb72ee098ddb38846a8f640947c698a314ac478945c35871661596d632fd1640d24ae1dac5c94d36fe24d3c554220e033174f2be0bb62ac607"

      msg = "How many roads must a man walk down, before you call him a man?"

      assert Base.encode16(hmac_sha512(key, msg), case: :lower) ==
               "6b8ac9a041586b269888778d0f938856d132dbc1cf186606e104f57552190490564919b35886620739a8e03739bf0fd49ab212f90f9a76164ac78d904f75cca6"
    end
  end
end
