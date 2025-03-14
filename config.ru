# frozen_string_literal: true

require 'rack'
require 'dotenv/load'
require_relative 'app'

run App.new
