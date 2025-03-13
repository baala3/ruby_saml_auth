# weby/router.rb

class Router
  def initialize
    @routes = {}
  end

  def get(path, &blk)
    @routes[path] = blk
  end

  def build_response(path)
    handler = @routes[path] || -> { "no route found for #{path}" }
    handler.call
  end
end
