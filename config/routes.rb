require_relative '../router'

Router.draw do
  get('/') { "Hello World!" }
  get('/acs') { "successfully authenticated" } #saml assertion consumer service
end
