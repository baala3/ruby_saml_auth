# frozen_string_literal: true

require 'rack'
require 'dotenv/load'
require_relative 'app'
require_relative 'handler/saml_handler'
require 'rack/session'

# session config
raise 'SESSION_SECRET environment variable must be set for security!' unless ENV['SESSION_SECRET']

# Configure session
use Rack::Session::Cookie,
  key: '_saml_session',
  secret: ENV['SESSION_SECRET'],
  # same_site: :lax,     # Allow cookies during SAML redirects
  expire_after: 3600,  # 1 hour in seconds
  path: '/',
  secure: true,
  http_only: true

run App.new
