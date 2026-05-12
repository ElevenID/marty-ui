# Find admin user
users = User.first(5)
users.each do |u|
  puts "User: id=#{u.id} name=#{u.name}"
end

# Try finding by name
admin = User.where(name: 'Admin').first
if admin
  puts "Found admin: id=#{admin.id} name=#{admin.name}"
else
  # Try finding with pseudonym
  pseudonym = Pseudonym.where(unique_id: 'admin@example.com').first
  if pseudonym
    puts "Found pseudonym: user_id=#{pseudonym.user_id}"
    admin = pseudonym.user
    puts "Admin user: id=#{admin.id} name=#{admin.name}"
  else
    puts "No admin found via pseudonym"
    # List pseudonyms
    Pseudonym.first(5).each do |p|
      puts "Pseudonym: id=#{p.id} unique_id=#{p.unique_id} user_id=#{p.user_id}"
    end
  end
end
