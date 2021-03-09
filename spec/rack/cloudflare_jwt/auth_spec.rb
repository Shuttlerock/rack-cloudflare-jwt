# frozen_string_literal: true

require 'spec_helper'

describe Rack::CloudflareJwt::Auth do
  let(:policy_aud) { 'xxx' }
  let(:payload)    { { foo: 'bar' } }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  let(:app) do
    described_class.new(inner_app, '/' => policy_aud)
  end

  describe 'initialization of #policies' do
    describe 'with policy auds: arg provided' do
      let(:args) { { '/admin' => 'aud-1', '/manager' => 'aud-2' } }
      let(:app) { described_class.new(inner_app, args) }

      it 'succeeds' do
        expect(app.policies).to eq args
      end
    end

    describe 'with no policy auds: arg provided' do
      it 'raises ArgumentError' do
        expect { described_class.new(inner_app, {}) }.to raise_error(ArgumentError)
      end
    end

    describe 'with policy auds: arg of invalid type' do
      it 'raises ArgumentError' do
        expect { described_class.new(inner_app, '/' => []) }.to raise_error(ArgumentError)
      end
    end

    describe 'with nil policy auds: arg provided' do
      it 'raises ArgumentError' do
        expect { described_class.new(inner_app, '/' => nil) }.to raise_error(ArgumentError)
      end
    end

    describe 'with empty policy auds: arg provided' do
      it 'raises ArgumentError' do
        expect { described_class.new(inner_app, '/' => '') }.to raise_error(ArgumentError)
      end
    end

    describe 'with spaces policy auds: arg provided' do
      it 'raises ArgumentError' do
        expect { described_class.new(inner_app, '/' => '     ') }.to raise_error(ArgumentError)
      end
    end

    describe 'when Hash keys contains non-String elements' do
      it 'raises an exception' do
        args = { %w[/foo /bar] => policy_aud }
        expect { described_class.new(inner_app, args) }.to raise_error(ArgumentError)
      end
    end

    describe 'when Hash keys contains empty String elements' do
      it 'raises an exception' do
        args = { '' => policy_aud }
        expect { described_class.new(inner_app, args) }.to raise_error(ArgumentError)
      end
    end

    describe 'when Hash keys contains elements that do not start with a /' do
      it 'raises an exception' do
        args = { 'bar' => policy_aud }
        expect { described_class.new(inner_app, args) }.to raise_error(ArgumentError)
      end
    end
  end

  describe '#verify_token' do
    let(:public_keys) { [OpenSSL::PKey::RSA.new(2048), OpenSSL::PKey::RSA.new(2048)] }
    let(:env)         { { described_class::HEADER_NAME => 'JWT token', described_class::PATH_INFO => '/admin' } }
    let(:logger)      { double(:logger, debug: true, info: true) } # rubocop:disable RSpec/VerifiedDoubles

    before do
      allow(app).to receive(:logger) { logger }
      allow(app).to receive(:public_keys) { public_keys }
    end

    context 'with valid token' do
      before do
        expect(app).to receive(:decode_token).and_raise(described_class::DecodeTokenError, 'foo') # rubocop:disable RSpec/ExpectInHook
        expect(app).to receive(:decode_token).and_return([{}, {}]) # rubocop:disable RSpec/ExpectInHook, RSpec/StubbedMock
      end

      after do
        app.send(:verify_token, env)
      end

      it { expect(inner_app).to receive(:call) }
      it { expect(logger).to receive(:info).with('foo') }
      it { expect(app).not_to receive(:return_error) }
    end

    context 'with invalid token' do
      before do
        allow(app).to receive(:decode_token).and_raise(described_class::DecodeTokenError, 'foo').twice
      end

      after do
        app.send(:verify_token, env)
      end

      it { expect(inner_app).not_to receive(:call) }
      it { expect(logger).to receive(:info).with('foo').twice }
      it { expect(app).to receive(:return_error) }
    end
  end

  describe '#decode_token' do
    it 'returns a token' do
      allow(Rack::JWT::Token).to receive(:decode).and_return([{}, {}])
      expect(app.send(:decode_token, 'foo', 'bar', 'cf-aud')).to eq [{}, {}]
    end

    [
      ::JWT::DecodeError,
      ::JWT::ExpiredSignature,
      ::JWT::ImmatureSignature,
      ::JWT::IncorrectAlgorithm,
      ::JWT::InvalidAudError,
      ::JWT::InvalidIatError,
      ::JWT::InvalidIssuerError,
      ::JWT::InvalidJtiError,
      ::JWT::InvalidSubError,
      ::JWT::VerificationError,
    ].each do |error_class|
      it "raises an error at #{error_class} error" do
        allow(Rack::JWT::Token).to receive(:decode).and_raise(error_class)
        expect { app.send(:decode_token, 'foo', 'bar', 'cf-aud') }.to raise_error(described_class::DecodeTokenError)
      end
    end
  end

  describe '#public_keys' do
    let(:cache) { double }

    before do
      allow(app).to receive(:cache) { cache }
      allow(cache).to receive(:fetch).and_yield(->(&block) { block.call })
      stub_request(:get, /#{described_class::CERTS_PATH}/o).to_return(status: 200, body: <<-JSON)
        {"keys":[{"kid":"b18283ffda890c840aa529674e75f9e59514409e5e55e2d0bad5795858e66228","kty":"RSA","alg":"RS256","use":"sig","e":"AQAB","n":"vy-V_OfLu6T57U-xRzSo9mHzgSwa6-z_qQFquwxp0SlqCGr04Wd2AO2u9pUA0MNNbp_GtIarbBvMqwMIkjIF-YkUS7Nme4H64nryTVPEnvMsOO1U0BNs1FxMhhBfy2f3gI6wfXfaRGiJuadZjCQVBjXor9sjhWAeU3ONGaOxUfgK-paB5VaLwcJh-RouG2GZvRI96Be23s0lmp0c-jkfY2yxmEhkwp5bvplEDPQL13mdigt1epUyAYTGYR22c06iViiZMQSPrsivfQXay8vCGQWWTEf5gS6DPsUkrc-7eFjYO_2nj7fJVf4IrFv54ZiFCXx0-UgSWtxH69hJkxdzpQ"},{"kid":"ac2790adb86610b4aac3b5b2512f755dd817af640afbcec7763635c701c4f566","kty":"RSA","alg":"RS256","use":"sig","e":"AQAB","n":"1bfNhQpbF5rC-9WeGJUXDAEwKS5BFaKBJI2RXqcabhTF5qErClzT147DOK5AXKarMV-zcLmOkK8qZklmxtJhcJ_MfH3c7rtGY6TqTvwU9SqBFq6YBDfZEVaxY-78xzWzYefilywE8cpzgYZXC56iRe0n-bCXu8HQD_p3CXExjRqS--Pmr1-y27XxG8QH7WR7ETr9gnfTqAvMPw-B3C7FxVcNTqorycpiow5Jiqr9SxyxZgZ79lwQ5WiQTeB0WLg7XfSK3kEqZ63NsAO03N6AQT-QQQprMYg8oZ85aOlbEh8TahRZXeZiJ2jbEFDJoyuqCwroA1kgzaLKjSpjeOzXHw"}],"public_cert":{"kid":"b18283ffda890c840aa529674e75f9e59514409e5e55e2d0bad5795858e66228","cert":"-----BEGIN CERTIFICATE-----\\nMIIDUTCCAjmgAwIBAgIRAJrBOaRWSa+JYrHKcIYyKu0wDQYJKoZIhvcNAQELBQAw\\nYjELMAkGA1UEBhMCVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4x\\nEzARBgNVBAoTCkNsb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3Mu\\nY29tMB4XDTIwMDIyNDE2MTEwOFoXDTIwMDQyNDE2MTEwOFowYjELMAkGA1UEBhMC\\nVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4xEzARBgNVBAoTCkNs\\nb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3MuY29tMIIBIjANBgkq\\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvy+V/OfLu6T57U+xRzSo9mHzgSwa6+z/\\nqQFquwxp0SlqCGr04Wd2AO2u9pUA0MNNbp/GtIarbBvMqwMIkjIF+YkUS7Nme4H6\\n4nryTVPEnvMsOO1U0BNs1FxMhhBfy2f3gI6wfXfaRGiJuadZjCQVBjXor9sjhWAe\\nU3ONGaOxUfgK+paB5VaLwcJh+RouG2GZvRI96Be23s0lmp0c+jkfY2yxmEhkwp5b\\nvplEDPQL13mdigt1epUyAYTGYR22c06iViiZMQSPrsivfQXay8vCGQWWTEf5gS6D\\nPsUkrc+7eFjYO/2nj7fJVf4IrFv54ZiFCXx0+UgSWtxH69hJkxdzpQIDAQABowIw\\nADANBgkqhkiG9w0BAQsFAAOCAQEAtoSWQEbcb2EhQOLaxXA+Dupfsy+cZNsjKhq8\\nlOex8RZvMsj69FPofiJTxAR3RTwQiWDTmx3kUvBbIr2IrKtUllD8/jO/GzAyd93c\\nrzZcLk3CNPNzKkbRFtM8qy4jBcupKsS2KHzDZ5uaKIad4i/s/9ld0r0fvjS3iiyJ\\nJDxwQXvzvf1fNOdb2na+tdKa/BBxz8blCybrICqH2dR2jw6YawUbGNU7zWVjR5Mc\\n2/3Q85l8qluZKARDUUL1uG3aeiIWhzuVvxYwisUBXIBvVqXB2V7xIiRAfIYscT4s\\ngktcHT8x59pgl1WI2UHBfJmZoecMrZXVZ5zxVOA9EVg88L/hSQ==\\n-----END CERTIFICATE-----\\n"}}
      JSON
    end

    it 'returns a keys' do
      expect(app.send(:public_keys, described_class::HEADER_HTTP_HOST => 'example.com')).to contain_exactly(instance_of(OpenSSL::PKey::RSA),
                                                                                                            instance_of(OpenSSL::PKey::RSA))
    end
  end
end
