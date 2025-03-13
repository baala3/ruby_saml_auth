# weby/router.rb
require "singleton"

class Router
  include Singleton

  class << self
    def draw(&blk)
      Router.instance.instance_exec(&blk)
    end
  end

  def initialize
    @routes = {}
  end

  def get(path, &blk)
    @routes[path] = blk
  end

  def build_response(path)
    if @routes.key?(path)
      @routes[path].call
    else
      [404, {'Content-Type' => 'text/html'}, ["no route found for #{path}"]]
    end
  end
end
