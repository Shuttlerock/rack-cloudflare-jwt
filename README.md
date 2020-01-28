# Rack::CloudflareJwt

[![CircleCI](https://circleci.com/gh/Shuttlerock/rack-cloudflare-jwt.svg?style=svg)](https://circleci.com/gh/Shuttlerock/rack-cloudflare-jwt)

## About

This gem provides CloudFlare JSON Web Token (JWT) based authentication.

## Requirements

- Ruby 2.6.0 or greater

## Installation

Add this line to your application's `Gemfile`:

```ruby
gem 'rack-cloudflare-jwt'
```

And then execute:

```
$ bundle install
```

Or install it directly with:

```
$ gem install rack-cloudflare-jwt
```

## Usage

`Rack::CloudflareJwt::Auth` accepts several configuration options. All options are passed in a single Ruby Hash:

* `policy_aud` : required : `String` : A Application Audience (AUD) Tag.

* `include_paths` : optional : Array : An Array of path strings representing paths that should be checked for the presence of a valid JWT token. Includes sub-paths as of specified paths as well (e.g. `%w(/docs)` includes `/docs/some/thing.html` also). Each path should start with a `/`. If a path not matches the current request path this entire middleware is skipped and no authentication or verification of tokens takes place.

### Rails

```ruby
require 'rack/cloudflare_jwt'
Rails.application.config.middleware.use Rack::CloudflareJwt::Auth, policy_aud: 'xxx.yyy.zzz', include_paths: %w[/foo]
```

## Contributing

1. Fork it ( https://github.com/Shuttlerock/rack-cloudflare-jwt/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
