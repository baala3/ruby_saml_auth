# frozen_string_literal: true

require_relative 'config/routes'

class App
  def call(env)
    Router.instance.build_response(env)
  end
end
