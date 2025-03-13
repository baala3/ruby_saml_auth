require_relative '../router'

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

  # Dynamic routes
  get('/acs') {
    [200, {'Content-Type' => 'text/html'}, ["successfully authenticated"]]
  }
end
