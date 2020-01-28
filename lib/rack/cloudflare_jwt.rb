# frozen_string_literal: true

require 'rack/cloudflare_jwt/version'

module Rack
  # CloudFlare JSON Web Token
  module CloudflareJwt
    autoload :Auth, 'rack/cloudflare_jwt/auth'
  end
end
