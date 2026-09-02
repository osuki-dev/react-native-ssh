#include <jni.h>
#include <fbjni/fbjni.h>
#include <cstdlib>
#include "OsukiSshOnLoad.hpp"

// aws-lc (the Rust core's crypto backend) weakly references jemalloc's
// `sdallocx` and calls it from OPENSSL_free whenever the symbol is non-NULL.
// React Native's libjsi.so / libreactnative.so export a *data object* named
// `sdallocx` (folly's jemalloc probe), which Bionic would bind that weak
// reference to — the call then jumps into non-executable memory (SIGSEGV on
// every aws-lc free, e.g. dropping an AES-GCM cipher on disconnect). Define it
// here, hidden, with system-allocator semantics so the reference resolves at
// link time and never leaves this library.
extern "C" __attribute__((visibility("hidden"))) void sdallocx(void* ptr, size_t /*size*/, int /*flags*/) {
  free(ptr);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return facebook::jni::initialize(vm, []() {
    margelo::nitro::ssh::registerAllNatives();
  });
}
