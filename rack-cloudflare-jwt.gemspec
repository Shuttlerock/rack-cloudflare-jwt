# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rack/cloudflare_jwt/version'

Gem::Specification.new do |spec|
  spec.name          = 'rack-cloudflare-jwt'
  spec.version       = Rack::CloudflareJwt::VERSION
  spec.authors       = ['Aleksei Vokhmin']
  spec.email         = ['avokhmin@gmail.com']
  spec.summary       = 'Rack middleware that provides authentication based on CloudFlare JSON Web Tokens.'
  spec.description   = 'Rack middleware that provides authentication based on CloudFlare JSON Web Tokens.'
  spec.homepage      = 'https://github.com/Shuttlerock/rack-cloudflare-jwt'
  spec.license       = 'MIT'

  spec.files         = Dir.glob('lib/**/*') + %w(LICENSE README.md)
  spec.require_paths = ['lib']
  spec.platform      = Gem::Platform::RUBY
  spec.required_ruby_version = '>= 2.6.0'

  spec.add_development_dependency 'bundler',             '>= 1.16.2'
  spec.add_development_dependency 'rack-test',           '>= 1.0.0'
  spec.add_development_dependency 'rake',                '>= 12.0.0'
  spec.add_development_dependency 'rspec',               '>= 3.8.0'
  spec.add_development_dependency 'rubocop-performance', '>= 1.0.0'
  spec.add_development_dependency 'rubocop-rspec',       '>= 2.0.0'
  spec.add_development_dependency 'simplecov',           '>= 0.16.0'
  spec.add_development_dependency 'webmock',             '>= 3.8.0'

  spec.add_runtime_dependency 'jwt', '>= 2.2', '< 2.8'
  spec.add_runtime_dependency 'multi_json'
  spec.add_runtime_dependency 'rack'
  spec.add_runtime_dependency 'rack-jwt', '>= 0.4.0'
  spec.metadata['rubygems_mfa_required'] = 'true'
end
