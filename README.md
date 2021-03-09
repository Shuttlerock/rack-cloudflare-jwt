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

`Rack::CloudflareJwt::Auth` accepts configuration options. All options are passed in a single Ruby `Hash<String, String>`. E.g. `{ '/admin' => 'aud-1', '/manager' => 'aud-2' }`.

* `Hash` key : `String` : A path string representing paths that should be checked for the presence of a valid JWT token. Includes sub-paths as of specified path as well (e.g. `/docs` includes `/docs/some/thing.html` also). Each path should start with a `/`. If a path not matches the current request path this entire middleware is skipped and no authentication or verification of tokens takes place.

* `Hash` value : `String` : A Application Audience (AUD) Tag.


### Rails

```ruby
Rails.application.config.middleware.use Rack::CloudflareJwt::Auth, '/my-path' => 'xxx.yyy.zzz'
```

## Contributing

1. Fork it ( https://github.com/Shuttlerock/rack-cloudflare-jwt/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
