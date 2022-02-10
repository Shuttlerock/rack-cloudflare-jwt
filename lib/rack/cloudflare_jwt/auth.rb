# frozen_string_literal: true

require 'jwt'
require 'multi_json'
require 'net/http'
require 'rack/jwt'

# Authentication middleware
#
# @see https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens/
class Rack::CloudflareJwt::Auth
  # Custom decode token error.
  class DecodeTokenError < StandardError; end

  # Certs path
  CERTS_PATH = '/cdn-cgi/access/certs'
  # Default algorithm
  DEFAULT_ALGORITHM = 'RS256'
  # CloudFlare JWT header.
  HEADER_NAME = 'HTTP_CF_ACCESS_JWT_ASSERTION'
  # Key for get current path.
  PATH_INFO = 'PATH_INFO'

  # Token regex.
  #
  # @see https://github.com/jwt/ruby-jwt/tree/v2.2.1#algorithms-and-usage
  TOKEN_REGEX = /
    ^(
    [a-zA-Z0-9\-_]+\.  # 1 or more chars followed by a single period
    [a-zA-Z0-9\-_]+\.  # 1 or more chars followed by a single period
    [a-zA-Z0-9\-_]+    # 1 or more chars, no trailing chars
    )$
  /x.freeze

  attr_reader :policies, :team_domain

  # Initializes middleware
  #
  # @example Initialize middleware in Rails
  #   config.middleware.use(
  #     Rack::CloudflareJwt::Auth,
  #     ENV['RACK_CLOUDFLARE_JWT_TEAM_DOMAIN'],
  #     '/admin'   => <cloudflare-aud-1>,
  #     '/manager' => <cloudflare-aud-2>,
  #   )
  #
  # @param team_domain [String] the Team Domain (e.g. 'test.cloudflareaccess.com').
  # @param policies [Hash<String, String>] the policies with paths and AUDs.
  def initialize(app, team_domain, policies = {})
    @app         = app
    @team_domain = team_domain
    @policies    = policies

    check_policy_auds!
    check_paths_type!
  end

  # Public: Call a middleware.
  def call(env)
    if !path_matches?(env)
      @app.call(env)
    elsif missing_auth_header?(env)
      return_error('Missing Authorization header')
    elsif invalid_auth_header?(env)
      return_error('Invalid Authorization header format')
    else
      verify_token(env)
    end
  end

  private

  # Private: Check policy auds.
  def check_policy_auds!
    raise ArgumentError, 'policies cannot be nil/empty' if policies.values.empty?

    policies.each_value do |policy_aud|
      next unless !policy_aud.is_a?(String) || policy_aud.strip.empty?

      raise ArgumentError, 'policy AUD argument cannot be nil/empty'
    end
  end

  # Private: Check paths type.
  def check_paths_type!
    policies.each_key do |path|
      raise ArgumentError, 'each key element must be a String' unless path.is_a?(String)
      raise ArgumentError, 'each key element must not be empty' if path.empty?
      raise ArgumentError, 'each key element must start with a /' unless path.start_with?('/')
    end
  end

  # Private: Verify a token.
  def verify_token(env)
    # extract the token from header.
    token         = env[HEADER_NAME]
    policy_aud    = policies.find { |path, _aud| env[PATH_INFO].start_with?(path) }&.last
    decoded_token = public_keys.find do |key|
      break decode_token(token, key.public_key, policy_aud)
    rescue DecodeTokenError => e
      logger.info e.message
      nil
    end

    if decoded_token
      logger.debug 'CloudFlare JWT token is valid'

      env['jwt.payload'] = decoded_token.first
      env['jwt.header']  = decoded_token.last
      @app.call(env)
    else
      return_error('Invalid token')
    end
  end

  # Private: Decode a token.
  #
  # @param token [String] the token.
  # @param secret [String] the public key.
  # @param policy_aud [String] the CloudFlare AUD.
  #
  # @example
  #
  #   [
  #     {"data"=>"test"}, # payload
  #     {"alg"=>"RS256"} # header
  #   ]
  #
  # @return [Array<Hash>] the token or `nil` at error.
  # @raise [DecodeTokenError] if the token is invalid.
  #
  # @see https://github.com/jwt/ruby-jwt/tree/v2.2.1#algorithms-and-usage
  def decode_token(token, secret, policy_aud)
    Rack::JWT::Token.decode(token, secret, true, aud: policy_aud, verify_aud: true, algorithm: DEFAULT_ALGORITHM)
  rescue ::JWT::VerificationError
    raise DecodeTokenError, 'Invalid JWT token : Signature Verification Error'
  rescue ::JWT::ExpiredSignature
    raise DecodeTokenError, 'Invalid JWT token : Expired Signature (exp)'
  rescue ::JWT::IncorrectAlgorithm
    raise DecodeTokenError, 'Invalid JWT token : Incorrect Key Algorithm'
  rescue ::JWT::ImmatureSignature
    raise DecodeTokenError, 'Invalid JWT token : Immature Signature (nbf)'
  rescue ::JWT::InvalidIssuerError
    raise DecodeTokenError, 'Invalid JWT token : Invalid Issuer (iss)'
  rescue ::JWT::InvalidIatError
    raise DecodeTokenError, 'Invalid JWT token : Invalid Issued At (iat)'
  rescue ::JWT::InvalidAudError
    raise DecodeTokenError, 'Invalid JWT token : Invalid Audience (aud)'
  rescue ::JWT::InvalidSubError
    raise DecodeTokenError, 'Invalid JWT token : Invalid Subject (sub)'
  rescue ::JWT::InvalidJtiError
    raise DecodeTokenError, 'Invalid JWT token : Invalid JWT ID (jti)'
  rescue ::JWT::DecodeError
    raise DecodeTokenError, 'Invalid JWT token : Decode Error'
  end

  # Private: Check if current path is in the policies.
  #
  # @return [Boolean] true if it is, false otherwise.
  def path_matches?(env)
    policies.empty? || policies.keys.any? { |ex| env[PATH_INFO].start_with?(ex) }
  end

  # Private: Check if auth header is invalid.
  #
  # @return [Boolean] true if it is, false otherwise.
  def invalid_auth_header?(env)
    env[HEADER_NAME] !~ TOKEN_REGEX
  end

  # Private: Check if no auth header.
  #
  # @return [Boolean] true if it is, false otherwise.
  def missing_auth_header?(env)
    env[HEADER_NAME].nil? || env[HEADER_NAME].strip.empty?
  end

  # Private: Return an error.
  def return_error(message)
    body    = { error: message }.to_json
    headers = { 'Content-Type' => 'application/json' }

    [403, headers, [body]]
  end

  # Private: Get public keys.
  #
  # @return [Array<OpenSSL::PKey::RSA>] the public keys.
  def public_keys
    fetch_public_keys_cached.map do |jwk_data|
      ::JWT::JWK.import(jwk_data).keypair
    end
  end

  # Private: Fetch public keys.
  #
  # @return [Array<Hash>] the public keys.
  def fetch_public_keys
    json = Net::HTTP.get(team_domain, CERTS_PATH)
    json.empty? ? [] : MultiJson.load(json, symbolize_keys: true).fetch(:keys)
  rescue StandardError
    []
  end

  # Private: Get cached public keys.
  #
  # Store a keys in the cache only 10 minutes.
  #
  # @return [Array<Hash>] the public keys.
  def fetch_public_keys_cached
    key = [self.class.name, '#secrets'].join('_')

    if defined? Rails
      Rails.cache.fetch(key, expires_in: 600) { fetch_public_keys }
    elsif defined? Padrino
      keys = Padrino.cache[key]
      keys || Padrino.cache.store(key, fetch_public_keys, expires: 600)
    else
      fetch_public_keys
    end
  end

  # Private: Get a logger.
  #
  # @return [ActiveSupport::Logger] the logger.
  def logger
    if defined? Rails
      Rails.logger
    elsif defined? Padrino
      Padrino.logger
    end
  end
end
