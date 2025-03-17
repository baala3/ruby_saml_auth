# frozen_string_literal: true

class SessionHandler
  def self.handle_home(env)
    session = env['rack.session']

    # Check if user is authenticated
    return [302, { 'Location' => '/' }, []] unless session[:email]

    # Read and process the template
    html_content = File.read('public/home.html')
                       .gsub('{{email}}', session[:email])
                       .gsub('{{first_name}}', session[:first_name])
                       .gsub('{{last_name}}', session[:last_name])
                       .gsub('{{name_id}}', session[:name_id])
                       .gsub('{{saml_request_id}}', session[:saml_request_id])

    [200, { 'Content-Type' => 'text/html' }, [html_content]]
  end

  def self.handle_logout(env)
    env['rack.session'].clear
    [302, { 'Location' => '/' }, []]
  end
end
