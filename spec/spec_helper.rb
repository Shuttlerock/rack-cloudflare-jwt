# frozen_string_literal: true

require 'simplecov'
SimpleCov.start do
  add_filter 'spec/'
end

require 'rspec'
require 'webmock/rspec'
require 'rack/test'
require 'rack/cloudflare_jwt'

RSpec.configure do |conf|
  conf.include Rack::Test::Methods
end
