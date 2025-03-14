class StaticFileHandler
  def self.serve_file(path, content_type)
    content = File.read(path)
    [200, {'Content-Type' => content_type}, [content]]
  end
end
