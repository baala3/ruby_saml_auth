require_relative '../router'

Router.draw do
  get('/') { "Hello World!" }
  get('/home') { "Home Page" }
  get('/about') { "About Page" }
end
