require_relative '../router'
require 'zlib'
require 'base64'
require 'uri'

# make sure to return an array from all routes
Router.draw do
  # Static file routes
  get('/') {
    content = File.read('public/index.html')
    [200, {'Content-Type' => 'text/html'}, [content]]
  }

  get('/styles.css') {
    content = File.read('public/styles.css')
    [200, {'Content-Type' => 'text/css'}, [content]]
  }

  get('/favicon.svg') {
    content = File.read('public/favicon.svg')
    [200, {'Content-Type' => 'image/svg+xml'}, [content]]
  }

  # Dynamic routes

  # note: acs should be either GET or POST and here `get` method is handling all requests to /acs,(i.e. GET, POST, etc. because we only check request path not request method)
  get('/acs') {
    [200, {'Content-Type' => 'text/html'}, ["successfully authenticated"]]
  }

  get('/auth/saml') {
    # Read and process the template
    template = File.read('xml/saml_request_template.xml')
    saml_request = template
      .gsub('{{HOST}}', ENV['HOST'])
      .gsub('{{OKTA_DOMAIN}}', ENV['OKTA_DOMAIN'])
      .gsub('{{OKTA_APP_PATH}}', ENV['OKTA_APP_PATH'])

    # Deflate and encode
    deflated_request = Zlib::Deflate.deflate(saml_request, Zlib::BEST_COMPRESSION)[2..-5]
    base64_request = Base64.strict_encode64(deflated_request)
    encoded_request = URI.encode_www_form_component(base64_request)

    redirect_url = "https://#{ENV['OKTA_DOMAIN']}/#{ENV['OKTA_APP_PATH']}?SAMLRequest=#{encoded_request}"
    [302, {'Location' => redirect_url}, []]
  }
end
