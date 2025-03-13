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
      '/' => 'public/index.html',
      '/styles.css' => 'public/styles.css'
    }
  end

  def get(path, &blk)
    @routes[path] = blk
  end

  def build_response(path)
    case
    when @static_paths.key?(path)
      content = File.read(@static_paths[path])
      content_type = path.end_with?('.css') ? 'text/css' : 'text/html' # css files are served as text/css
      [200, {'Content-Type' => content_type}, [content]]
    when @routes.key?(path)
      @routes[path].call # should always return an array
    else
      [404, {'Content-Type' => 'text/html'}, ["no route found for #{path}"]]
    end
  end
end
