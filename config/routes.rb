# frozen_string_literal: true

require_relative '../router'
require_relative '../handler/static_file_handler'
require_relative '../handler/saml_handler'

# make sure to return an array from all routes
Router.draw do
  # Static file routes
  get('/') { StaticFileHandler.serve_file('public/index.html', 'text/html') }
  get('/styles.css') { StaticFileHandler.serve_file('public/styles.css', 'text/css') }
  get('/favicon.svg') { StaticFileHandler.serve_file('public/favicon.svg', 'image/svg+xml') }
  get('/home') { StaticFileHandler.serve_file('public/home.html', 'text/html') }

  # SAML routes
  get('/auth/saml') { SamlHandler.handle_auth_request }
  # NOTE: acs should be POST and here `get` method is also handling POST
  get('/acs') { |env| SamlHandler.handle_acs(env) }
end
