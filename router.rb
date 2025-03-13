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
    @static_paths = {
      '/' => 'public/index.html'
    }
  end

  def get(path, &blk)
    @routes[path] = blk
  end

  def build_response(path)
    case
    when @static_paths.key?(path)
      File.read(@static_paths[path])
    when @routes.key?(path)
      @routes[path].call
    else
      "no route found for #{path}"
    end
  end
end
