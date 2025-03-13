require_relative './router'

class App
  attr_reader :router

  def initialize
    @router = Router.new

    router.get('/') do
      'Hello World!'
    end

    router.get('/home') do
      'Home Page'
    end

    router.get('/about') do
      'About Page'
    end
  end

  def call(env)
    headers = {
      'Content-Type' => 'text/html'
    }

    responseHTML = router.build_response(env['PATH_INFO'])

    [200, headers, [responseHTML]]
  end
end
