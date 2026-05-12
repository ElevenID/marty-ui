# Generate Canvas LTI signing keys
# Lti::KeyStorage uses CanvasSecurity::KeyStorage

begin
  if defined?(Lti) && defined?(Lti::KeyStorage)
    puts "Lti::KeyStorage is defined: #{Lti::KeyStorage.class}"
    
    # Try to get public keyset (should auto-generate keys)
    keyset = Lti::KeyStorage.public_keyset
    puts "Public keyset: #{keyset.inspect}"
    
    if keyset.respond_to?(:as_json)
      json = keyset.as_json
      puts "JWKS keys count: #{json[:keys]&.length || 0}"
      if json[:keys] && json[:keys].length > 0
        puts "Keys generated successfully!"
        puts json.to_json
      end
    end
  else
    puts "Lti::KeyStorage is NOT defined"
    puts "Lti defined: #{defined?(Lti)}"
    
    # Try Canvas::OAuth instead
    if defined?(Canvas::OAuth::KeyStorage)
      puts "Trying Canvas::OAuth::KeyStorage..."
      keyset = Canvas::OAuth::KeyStorage.public_keyset
      puts "Result: #{keyset.inspect}"
    end
  end

  puts "\nDone."
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts e.backtrace.first(8).join("\n")
end
