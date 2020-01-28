# frozen_string_literal: true

require 'spec_helper'

describe Rack::CloudflareJwt::Auth do
  let(:policy_aud) { 'xxx' }
  let(:payload)    { { foo: 'bar' } }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  let(:app) do
    described_class.new(inner_app, policy_aud: policy_aud)
  end

  describe 'initialization of' do
    describe 'policy_aud' do
      describe 'with only policy_aud: arg provided' do
        let(:app) { described_class.new(inner_app, policy_aud: policy_aud) }
        it 'succeeds' do
          expect(app.policy_aud).to eq(policy_aud)
        end
      end

      describe 'with no policy_aud: arg provided' do
        it 'raises ArgumentError' do
          expect { described_class.new(inner_app, {}) }.to raise_error(ArgumentError)
        end
      end

      describe 'with policy_aud: arg of invalid type' do
        it 'raises ArgumentError' do
          expect { described_class.new(inner_app, policy_aud: []) }.to raise_error(ArgumentError)
        end
      end

      describe 'with nil policy_aud: arg provided' do
        it 'raises ArgumentError' do
          expect { described_class.new(inner_app, policy_aud: nil) }.to raise_error(ArgumentError)
        end
      end

      describe 'with empty policy_aud: arg provided' do
        it 'raises ArgumentError' do
          expect { described_class.new(inner_app, policy_aud: '') }.to raise_error(ArgumentError)
        end
      end

      describe 'with spaces policy_aud: arg provided' do
        it 'raises ArgumentError' do
          expect { described_class.new(inner_app, policy_aud: '     ') }.to raise_error(ArgumentError)
        end
      end
    end

    describe 'include_paths' do
      describe 'when a type other than Array provided' do
        it 'raises an exception' do
          args = { policy_aud: policy_aud, include_paths: {} }
          expect { described_class.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end

      describe 'when Array contains non-String elements' do
        it 'raises an exception' do
          args = { policy_aud: policy_aud, include_paths: ['/foo', nil, '/bar'] }
          expect { described_class.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end

      describe 'when Array contains empty String elements' do
        it 'raises an exception' do
          args = { policy_aud: policy_aud, include_paths: ['/foo', '', '/bar'] }
          expect { described_class.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end

      describe 'when Array contains elements that do not start with a /' do
        it 'raises an exception' do
          args = { policy_aud: policy_aud, include_paths: ['/foo', 'bar', '/baz'] }
          expect { described_class.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end
    end
  end
end
