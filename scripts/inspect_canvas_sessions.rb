setting = PluginSetting.where(name: 'sessions').first
if setting.nil?
  puts 'NO_SESSIONS_PLUGIN_SETTING'
else
  puts "id=#{setting.id}"
  puts "name=#{setting.name}"
  puts "settings=#{setting.settings.inspect}"
end
