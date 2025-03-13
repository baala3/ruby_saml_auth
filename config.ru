require "rack"
require "dotenv/load"
require_relative "app"

run App.new
