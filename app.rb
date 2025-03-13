require_relative './config/routes'

class App
  def call(env)
    Router.instance.build_response(env['PATH_INFO'])
  end
end
