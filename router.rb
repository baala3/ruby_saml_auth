# frozen_string_literal: true

require 'singleton'

class Router
  include Singleton

  class << self
    def draw(&)
      Router.instance.instance_exec(&)
    end
  end

  def initialize
    @routes = {}
  end

  def get(path, &blk)
    @routes[path] = blk
  end

  def build_response(env)
    path = env['PATH_INFO']
    if @routes.key?(path)
      @routes[path].call(env)
    else
      [404, { 'Content-Type' => 'text/html' }, ["no route found for #{path}"]]
    end
  end
end
