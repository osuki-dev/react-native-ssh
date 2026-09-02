#include "HybridSshClient.hpp"
#include "HybridSshConnection.hpp"
#include "RnsshBridge.hpp"
#include "SshAuthSpec.hpp"
#include "SshConnectOptionsSpec.hpp"
#include "SshKeyInfo.hpp"
#include "SshKeyPair.hpp"
#include "rnssh.h"
#include <cmath>
#include <vector>

namespace margelo::nitro::ssh {

using namespace bridge;

std::string HybridSshClient::getVersion() {
  return str(rnssh_version());
}

std::shared_ptr<Promise<std::shared_ptr<HybridSshConnectionSpec>>>
HybridSshClient::connect(const SshConnectOptionsSpec& options, const SshConnectionHandlers& handlers) {
  auto promise = Promise<std::shared_ptr<HybridSshConnectionSpec>>::create();

  // Validate what we can synchronously so the error surfaces as a rejected
  // promise with a clear code rather than a Rust-side failure.
  if (options.host.empty()) {
    promise->reject(makeError(1, "host must not be empty"));
    return promise;
  }
  if (options.username.empty()) {
    promise->reject(makeError(1, "username must not be empty"));
    return promise;
  }
  if (options.port < 1 || options.port > 65535 || std::floor(options.port) != options.port) {
    promise->reject(makeError(1, "port must be an integer in 1..65535"));
    return promise;
  }

  RnsshConnectOptions o;
  o.host = options.host.c_str();
  o.port = static_cast<uint16_t>(options.port);
  o.username = options.username.c_str();
  switch (options.auth.method) {
    case SshAuthMethod::NONE: o.auth_method = RnsshAuthMethod_None; break;
    case SshAuthMethod::PASSWORD: o.auth_method = RnsshAuthMethod_Password; break;
    case SshAuthMethod::PUBLICKEY: o.auth_method = RnsshAuthMethod_PublicKey; break;
    case SshAuthMethod::KEYBOARDINTERACTIVE: o.auth_method = RnsshAuthMethod_KeyboardInteractive; break;
  }
  o.password = cstrOrNull(options.auth.password);
  o.private_key = cstrOrNull(options.auth.privateKey);
  o.passphrase = cstrOrNull(options.auth.passphrase);
  auto u = [](double v) { return v > 0 ? static_cast<uint32_t>(v) : 0u; };
  o.connect_timeout_ms = u(options.connectTimeoutMs);
  o.keepalive_interval_ms = u(options.keepaliveIntervalMs);
  o.keepalive_max = u(options.keepaliveMax);
  std::vector<const char*> hostKeyAlgs;
  if (options.hostKeyAlgorithms.has_value()) {
    hostKeyAlgs.reserve(options.hostKeyAlgorithms->size());
    for (const auto& a : *options.hostKeyAlgorithms) hostKeyAlgs.push_back(a.c_str());
  }
  o.host_key_algorithms = hostKeyAlgs.empty() ? nullptr : hostKeyAlgs.data();
  o.host_key_algorithm_count = hostKeyAlgs.size();

  if (o.auth_method == RnsshAuthMethod_Password && o.password == nullptr) {
    promise->reject(makeError(1, "auth.password is required for password authentication"));
    return promise;
  }
  if (o.auth_method == RnsshAuthMethod_PublicKey && o.private_key == nullptr) {
    promise->reject(makeError(1, "auth.privateKey is required for public key authentication"));
    return promise;
  }

  auto* ctx = new ConnectionContext{handlers, promise, options.host, options.port, options.username};
  RnsshConnectionCallbacks cbs = ConnectionContext::callbacks(ctx);
  // Rust owns `ctx` from here (frees it through `release`). Strings in `o`
  // are copied inside rnssh_connect before it returns.
  uint64_t id = rnssh_connect(&o, &cbs);
  if (id == 0) {
    // Only happens for NULL pointers, which we never pass; keep the promise sane anyway.
    delete ctx;
    promise->reject(makeError(12, "rnssh_connect refused the request"));
    return promise;
  }
  if (handlers.onStarted.has_value()) {
    // `handlers` is our own copy; ctx may already be gone if Rust failed instantly.
    (*handlers.onStarted)(static_cast<double>(id));
  }
  return promise;
}

void HybridSshClient::cancelConnect(double id) {
  if (id > 0) rnssh_connection_cancel(static_cast<uint64_t>(id));
}

namespace {
SshKeyInfo keyInfoFrom(RnsshKeyResult& r) {
  SshKeyInfo info(str(r.algorithm), str(r.public_key), str(r.fingerprint), str(r.comment), r.encrypted);
  rnssh_key_result_free(&r);
  return info;
}
} // namespace

std::shared_ptr<Promise<SshKeyPair>> HybridSshClient::generateKeyPair(SshKeyType type,
                                                                      const std::optional<std::string>& comment,
                                                                      const std::optional<std::string>& passphrase) {
  uint32_t kt = static_cast<uint32_t>(type);
  return Promise<SshKeyPair>::async([kt, comment, passphrase]() -> SshKeyPair {
    RnsshKeyResult r = rnssh_generate_key_pair(kt, cstrOrNull(comment), cstrOrNull(passphrase));
    if (r.code != RNSSH_OK) {
      SshNativeError err(r.code, str(r.message));
      rnssh_key_result_free(&r);
      throw err;
    }
    SshKeyPair pair(str(r.private_key), str(r.public_key), str(r.fingerprint));
    rnssh_key_result_free(&r);
    return pair;
  });
}

SshKeyInfo HybridSshClient::inspectPrivateKey(const std::string& privateKey, const std::optional<std::string>& passphrase) {
  RnsshKeyResult r = rnssh_inspect_private_key(privateKey.c_str(), cstrOrNull(passphrase));
  if (r.code != RNSSH_OK) {
    SshNativeError err(r.code, str(r.message));
    rnssh_key_result_free(&r);
    throw err;
  }
  return keyInfoFrom(r);
}

} // namespace margelo::nitro::ssh
