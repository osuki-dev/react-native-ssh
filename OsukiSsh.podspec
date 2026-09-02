require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "OsukiSsh"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/osuki-dev/react-native-ssh.git", :tag => "v#{s.version}" }

  # Nitro HybridObjects (C++) on top of the Rust C ABI.
  s.source_files = [
    "cpp/**/*.{h,hpp,cpp}",
  ]
  s.private_header_files = [
    "cpp/**/*.{h,hpp}",
  ]

  # Prebuilt Rust static library (device + simulator), produced by
  # scripts/build-rust-ios.sh. Contains russh + tokio + aws-lc.
  s.vendored_frameworks = "ios/RnsshFFI.xcframework"

  s.pod_target_xcconfig = {
    "GCC_OPTIMIZATION_LEVEL" => "2",
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++20",
  }
  # librnssh_ffi.a only references libSystem (getaddrinfo, libdispatch,
  # clock_gettime, pthreads): no Security / CoreFoundation / resolv needed.
  # libc++ is already linked by React / NitroModules; re-adding it only
  # produces an "ignoring duplicate libraries: '-lc++'" linker warning.

  load 'nitrogen/generated/ios/OsukiSsh+autolinking.rb'
  add_nitrogen_files(s)

  s.dependency 'React-jsi'
  s.dependency 'React-callinvoker'
  install_modules_dependencies(s)
end
