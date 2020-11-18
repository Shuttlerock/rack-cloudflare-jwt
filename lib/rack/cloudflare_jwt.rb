# frozen_string_literal: true

require 'rack/cloudflare_jwt/version'

module Rack::CloudflareJwt
  # CloudFlare JSON Web Token

  autoload :Auth, 'rack/cloudflare_jwt/auth'
end
