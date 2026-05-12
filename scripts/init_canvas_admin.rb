# Initialize Canvas with admin user and required data

begin
  # Check existing accounts
  puts "Accounts:"
  Account.all.each { |a| puts "  id=#{a.id} name=#{a.name}" }
  
  # Create admin pseudonym + user
  account = Account.find(1)  # Default Account
  puts "\nUsing account: #{account.name} (id=#{account.id})"
  
  # Create user
  user = User.create!(
    name: 'Admin User',
    workflow_state: 'registered'
  )
  puts "Created user: id=#{user.id} name=#{user.name}"
  
  # Create pseudonym for login
  pseudonym = Pseudonym.create!(
    user: user,
    account: account,
    unique_id: 'admin@example.com',
    password: 'readystack123',
    password_confirmation: 'readystack123',
    workflow_state: 'active'
  )
  puts "Created pseudonym: id=#{pseudonym.id} unique_id=#{pseudonym.unique_id}"
  
  # Make admin
  account_admin = AccountUser.create!(
    user: user,
    account: account,
    role: account.available_account_roles.first || Role.get_built_in_role('AccountAdmin')
  )
  puts "Created account admin: id=#{account_admin.id}"
  
  puts "\n=== Setup Complete ==="
  puts "Login: admin@example.com"
  puts "Password: readystack123"
  puts "URL: http://localhost:8088/login/canvas"
  
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts e.backtrace.first(5).join("\n")
end
