# frozen_string_literal: true

require_relative '../router'
require_relative '../handler/static_file_handler'
require_relative '../handler/saml_handler'
require_relative '../handler/session_handler'

# make sure to return an array from all routes
Router.draw do
  # Static file routes
  get('/') { StaticFileHandler.serve_file('public/index.html', 'text/html') }
  get('/styles.css') { StaticFileHandler.serve_file('public/styles.css', 'text/css') }
  get('/favicon.svg') { StaticFileHandler.serve_file('public/favicon.svg', 'image/svg+xml') }
  get('/js/notifications.js') { StaticFileHandler.serve_file('public/js/notifications.js', 'application/javascript') }

  # SAML routes
  get('/auth/saml') { |env| SamlHandler.handle_auth_request(env) }
  # NOTE: acs should be POST and here `get` method is also handling POST
  get('/acs') { |env| SamlHandler.handle_acs(env) }

  # protected routes
  get('/home') { |env| SessionHandler.handle_home(env) }
  get('/logout') { |env| SessionHandler.handle_logout(env) }
  get('/logout/saml') { |env| SamlHandler.handle_logout_request(env) }
end
