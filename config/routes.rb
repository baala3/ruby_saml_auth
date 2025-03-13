require_relative '../router'

# make sure to return an array from all routes
Router.draw do
  get('/') {
    [200, {'Content-Type' => 'text/html'}, ["Hello World!"]]
  }

  get('/acs') {
    [200, {'Content-Type' => 'text/html'}, ["successfully authenticated"]]
  }
end
