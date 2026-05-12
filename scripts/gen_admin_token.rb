# Check Canvas API endpoints and test authentication

begin
  # Check available API routes
  puts "Checking Canvas API endpoints..."
  
  # Try to find the admin user
  pseudonym = Pseudonym.first
  if pseudonym
    puts "Found pseudonym: id=#{pseudonym.id} unique_id=#{pseudonym.unique_id}"
    admin = pseudonym.user
    puts "Admin user: id=#{admin.id} name=#{admin.name}"
    
    # Create an access token for the admin user
    token = admin.access_tokens.create!(purpose: 'elevenid-setup')
    puts "Access token: #{token.token}"
    puts "Token full_token: #{token.full_token}"
  else
    puts "No pseudonyms found in database!"
    puts "Pseudonym count: #{Pseudonym.count}"
    puts "User count: #{User.count}"
    
    # List first few users
    User.first(5).each do |u|
      puts "User: id=#{u.id}"
    end
  end
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts e.backtrace.first(5).join("\n")
end
