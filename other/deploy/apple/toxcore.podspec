Pod::Spec.new do |s|
  s.name             = "toxcore"
  s.version          = "0.2.21"
  s.summary          = "Cocoapods wrapper for toxcore"
  s.homepage         = "https://github.com/TokTok/c-toxcore"
  s.license          = 'GPLv3'
  s.author           = { "Iphigenia Df" => "iphydf@gmail.com" }
  s.source           = {
      :git => "https://github.com/TokTok/c-toxcore.git",
      :tag => s.version.to_s,
      :submodules => true
  }

  s.requires_arc = false

  s.ios.deployment_target = '12.0'
  s.osx.deployment_target = '10.15'

  s.vendored_frameworks = 'Tox.xcframework'
  s.xcconfig = { 'FRAMEWORK_SEARCH_PATHS' => '"${PODS_ROOT}"' }
  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'smoke-test.c'
  end
end
