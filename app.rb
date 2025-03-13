require_relative './config/routes'

class App
  def call(env)
    headers = {
      'Content-Type' => 'text/html'
    }

    responseHTML = Router.instance.build_response(env['PATH_INFO'])

    [200, headers, [responseHTML]]
  end
end
