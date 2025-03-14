require_relative '../router'
require_relative '../handler/static_file_handler'
require_relative '../handler/saml_handler'

# make sure to return an array from all routes
Router.draw do
  # Static file routes
  get('/') { StaticFileHandler.serve_file('public/index.html', 'text/html') }
  get('/styles.css') { StaticFileHandler.serve_file('public/styles.css', 'text/css') }
  get('/favicon.svg') { StaticFileHandler.serve_file('public/favicon.svg', 'image/svg+xml') }

  # SAML routes
  get('/auth/saml') { SamlHandler.handle_auth_request }
  # note: acs should be either GET or POST and here `get` method is handling all requests to /acs,(i.e. GET, POST, etc. because we only check request path not request method)
  get('/acs') {|env| SamlHandler.handle_acs(env) }
end
