#!/usr/bin/env ruby
# Script to generate Canvas API token for admin user

user = User.find_by(email: 'admin@example.com')
if user
  token = user.access_tokens.create!(purpose: 'elevenid-integration')
  puts token.token
else
  puts "ERROR: admin@example.com user not found"
  exit 1
end
