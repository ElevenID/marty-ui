# Generate admin API token and seed course/tool

require 'uri'

lti_base_url = ENV.fetch('CANVAS_LTI_EXPERIENCE_BASE_URL', 'https://beta.elevenidllc.com').sub(%r{/+$}, '')
connector_id = ENV.fetch('CANVAS_CONNECTOR_ID', '67f60f26-67aa-405f-9e04-b48165d49c61')
tool_url = "#{lti_base_url}/v1/integrations/canvas/lti/experience-login/#{connector_id}"
tool_domain = URI.parse(lti_base_url).host

begin
  admin = User.find(1)
  puts "Admin user: id=#{admin.id} name=#{admin.name}"
  
  # Create access token
  token = admin.access_tokens.create!(purpose: 'elevenid-integration')
  puts "Access token: #{token.full_token}"
  
  # Create course
  course = Course.create!(
    name: 'ElevenID LTI Test Course',
    course_code: 'ELEVENID-LTI-101',
    sis_source_id: 'elevenid_lti_test',
    account: Account.find(1),
    workflow_state: 'available'
  )
  puts "Course created: id=#{course.id} name=#{course.name}"
  
  # Create test learner
  learner = User.create!(name: 'ElevenID Test Learner', workflow_state: 'registered')
  learner_pseudonym = Pseudonym.create!(
    user: learner,
    account: Account.find(1),
    unique_id: 'learner+elevenid@example.edu',
    password: 'ChangeMe123!',
    password_confirmation: 'ChangeMe123!',
    workflow_state: 'active'
  )
  
  # Enroll learner
  enrollment = Enrollment.create!(
    user: learner,
    course: course,
    type: 'StudentEnrollment',
    workflow_state: 'active'
  )
  puts "Learner enrolled: user_id=#{learner.id} in course_id=#{course.id}"
  
  # Create external tool (LTI 1.3)
  # First get the developer key
  dev_key = DeveloperKey.find_by(name: 'canvas-real-client-id')
  if dev_key
    puts "Found dev key: id=#{dev_key.id}"
    
    tool = ContextExternalTool.create!(
      context: course,
      name: 'Canvas Real LMS',
      url: tool_url,
      domain: tool_domain,
      consumer_key: 'canvas-real-client-id',
      shared_secret: 'not-used-in-lti-1-3',
      privacy_level: 'public',
      workflow_state: 'public',
      developer_key: dev_key,
      lti_version: '1.3',
      settings: {
        platform: 'canvas',
        privacy_level: 'public',
        icon_url: nil,
        text: 'ElevenID Credential Issuance'
      }
    )
    puts "External tool created: id=#{tool.id} name=#{tool.name}"
  else
    puts "WARNING: No developer key found - tool will need manual LTI config"
  end
  
  puts "\n=== Setup Complete ==="
  puts "Admin token: #{token.full_token}"
  puts "Course ID: #{course.id}"
  puts "Learner: learner+elevenid@example.edu / ChangeMe123!"
  
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts e.backtrace.first(5).join("\n")
end
