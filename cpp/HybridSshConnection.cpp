#include "HybridSshConnection.hpp"
#include "HybridSshForward.hpp"
#include "HybridSshShell.hpp"
#include "SshForwardOptionsSpec.hpp"
#include "RnsshBridge.hpp"
#include "SshExecResult.hpp"
#include "SshExecTextResult.hpp"
#include "SshKeyboardInteractiveChallenge.hpp"
#include "SshShellOptionsSpec.hpp"
#include "rnssh.h"
#include <vector>

namespace margelo::nitro::ssh {

using namespace bridge;

bool HybridSshConnection::getIsConnected() {
  return rnssh_connection_is_connected(_id);
}

std::shared_ptr<Promise<std::shared_ptr<HybridSshShellSpec>>>
HybridSshConnection::openShell(const SshShellOptionsSpec& options, const SshShellHandlers& handlers) {
  auto promise = Promise<std::shared_ptr<HybridSshShellSpec>>::create();

  // Flatten env into parallel C arrays; the strings only need to outlive the call.
  std::vector<std::string> envKeys, envValues;
  std::vector<const char*> envKeyPtrs, envValuePtrs;
  if (options.env.has_value()) {
    envKeys.reserve(options.env->size());
    envValues.reserve(options.env->size());
    for (const auto& [k, v] : *options.env) {
      envKeys.push_back(k);
      envValues.push_back(v);
    }
    for (size_t i = 0; i < envKeys.size(); i++) {
      envKeyPtrs.push_back(envKeys[i].c_str());
      envValuePtrs.push_back(envValues[i].c_str());
    }
  }

  auto u = [](double v) { return v > 0 ? static_cast<uint32_t>(v) : 0u; };
  RnsshShellOptions o;
  o.term = options.term.c_str();
  o.cols = u(options.cols);
  o.rows = u(options.rows);
  o.width_px = u(options.widthPx);
  o.height_px = u(options.heightPx);
  o.env_keys = envKeyPtrs.empty() ? nullptr : envKeyPtrs.data();
  o.env_values = envValuePtrs.empty() ? nullptr : envValuePtrs.data();
  o.env_count = envKeyPtrs.size();
  o.command = cstrOrNull(options.command);

  auto* ctx = new ShellContext{handlers, promise};
  RnsshShellCallbacks cbs = ShellContext::callbacks(ctx);
  // Rust owns `ctx` from here on (frees it through `release`) and may fire
  // `on_opened` + `release` on a tokio thread before this call returns, so
  // nothing touches `ctx` afterwards.
  uint64_t id = rnssh_shell_open(_id, &o, &cbs);
  if (id == 0) {
    delete ctx; // Rust never saw it (NULL arguments only).
    promise->reject(makeError(12, "rnssh_shell_open refused the request"));
  }
  return promise;
}

namespace {
struct ExecContext {
  std::shared_ptr<Promise<SshExecResult>> promise;

  static void onResult(void* user, const RnsshExecResult* r) {
    std::unique_ptr<ExecContext> ctx(static_cast<ExecContext*>(user));
    if (r == nullptr) {
      ctx->promise->reject(makeError(12, "exec returned no result"));
      return;
    }
    if (r->code != RNSSH_OK) {
      ctx->promise->reject(makeError(r->code, r->message));
      return;
    }
    // Buffers are only valid during this callback → copy.
    ctx->promise->resolve(SshExecResult(copyBytes(r->stdout, r->stdout_len), copyBytes(r->stderr, r->stderr_len),
                                        r->has_exit_code ? static_cast<double>(r->exit_code) : -1.0));
  }
};
} // namespace

std::shared_ptr<Promise<SshExecResult>> HybridSshConnection::exec(const std::string& command) {
  auto promise = Promise<SshExecResult>::create();
  RnsshExecCallback cb;
  cb.user = new ExecContext{promise};
  cb.on_result = &ExecContext::onResult;
  rnssh_connection_exec(_id, command.c_str(), cb);
  return promise;
}

namespace {
struct ExecTextContext {
  std::shared_ptr<Promise<SshExecTextResult>> promise;

  static void onResult(void* user, const RnsshExecResult* r) {
    std::unique_ptr<ExecTextContext> ctx(static_cast<ExecTextContext*>(user));
    if (r == nullptr) {
      ctx->promise->reject(makeError(12, "exec returned no result"));
      return;
    }
    if (r->code != RNSSH_OK) {
      ctx->promise->reject(makeError(r->code, r->message));
      return;
    }
    ctx->promise->resolve(SshExecTextResult(sanitizeUtf8(r->stdout, r->stdout_len), sanitizeUtf8(r->stderr, r->stderr_len),
                                            r->has_exit_code ? static_cast<double>(r->exit_code) : -1.0));
  }
};
} // namespace

std::shared_ptr<Promise<SshExecTextResult>> HybridSshConnection::execText(const std::string& command) {
  auto promise = Promise<SshExecTextResult>::create();
  RnsshExecCallback cb;
  cb.user = new ExecTextContext{promise};
  cb.on_result = &ExecTextContext::onResult;
  rnssh_connection_exec(_id, command.c_str(), cb);
  return promise;
}

std::shared_ptr<Promise<std::shared_ptr<HybridSshLocalForwardSpec>>>
HybridSshConnection::forwardLocal(const SshForwardOptionsSpec& options, const SshForwardHandlers& handlers) {
  auto promise = Promise<std::shared_ptr<HybridSshLocalForwardSpec>>::create();
  auto port = [](double v) -> uint16_t { return (v > 0 && v <= 65535) ? static_cast<uint16_t>(v) : 0; };
  if (options.remoteHost.empty() || port(options.remotePort) == 0) {
    promise->reject(makeError(1, "remoteHost and remotePort are required"));
    return promise;
  }
  RnsshForwardOptions o;
  o.bind = options.bindAddress.empty() ? nullptr : options.bindAddress.c_str();
  o.local_port = port(options.localPort);
  o.remote_host = options.remoteHost.c_str();
  o.remote_port = port(options.remotePort);
  o.max_connections = options.maxConnections > 0 ? static_cast<uint32_t>(options.maxConnections) : 0u;

  auto* ctx = new ForwardContext{handlers, promise};
  RnsshForwardCallbacks cbs = ForwardContext::callbacks(ctx);
  // Rust owns `ctx` from here on; every callback carries the forward id.
  uint64_t id = rnssh_forward_local(_id, &o, &cbs);
  if (id == 0) {
    delete ctx;
    promise->reject(makeError(12, "rnssh_forward_local refused the request"));
  }
  return promise;
}

std::shared_ptr<Promise<void>> HybridSshConnection::disconnect() {
  auto promise = Promise<void>::create();
  rnssh_connection_disconnect(_id, VoidCompletion::make(promise));
  return promise;
}

// ---------------------------------------------------------------------------
// ConnectionContext — Rust → JS event plumbing
// ---------------------------------------------------------------------------

namespace {

void onHostKey(void* user, uint64_t conn, const RnsshHostKey* key) {
  auto* ctx = static_cast<ConnectionContext*>(user);
  auto hostKey = toHostKey(key);
  try {
    // Async JS callback: the outer promise resolves once the JS function ran
    // (on the JS thread); it yields the Promise<boolean> the app returned.
    auto outer = ctx->handlers.verifyHostKey(hostKey);
    outer->addOnResolvedListener([conn](const std::shared_ptr<Promise<bool>>& inner) {
      if (inner == nullptr) {
        rnssh_connection_respond_host_key(conn, false);
        return;
      }
      inner->addOnResolvedListener([conn](const bool& accept) { rnssh_connection_respond_host_key(conn, accept); });
      inner->addOnRejectedListener([conn](const std::exception_ptr&) { rnssh_connection_respond_host_key(conn, false); });
    });
    outer->addOnRejectedListener([conn](const std::exception_ptr&) { rnssh_connection_respond_host_key(conn, false); });
  } catch (...) {
    rnssh_connection_respond_host_key(conn, false);
  }
}

void onKeyboardInteractive(void* user, uint64_t conn, const RnsshKbiChallenge* challenge) {
  auto* ctx = static_cast<ConnectionContext*>(user);
  if (!ctx->handlers.onKeyboardInteractive.has_value() || challenge == nullptr) {
    rnssh_connection_respond_kbi(conn, nullptr, 0);
    return;
  }
  std::vector<SshKeyboardInteractivePrompt> prompts;
  prompts.reserve(challenge->prompt_count);
  for (size_t i = 0; i < challenge->prompt_count; i++) {
    prompts.emplace_back(str(challenge->prompts[i].prompt), challenge->prompts[i].echo);
  }
  SshKeyboardInteractiveChallenge c(str(challenge->name), str(challenge->instruction), std::move(prompts));

  auto cancel = [conn]() { rnssh_connection_respond_kbi(conn, nullptr, 0); };
  try {
    auto outer = (*ctx->handlers.onKeyboardInteractive)(c);
    outer->addOnResolvedListener(
        [conn, cancel](const std::shared_ptr<Promise<std::optional<std::vector<std::string>>>>& inner) {
          if (inner == nullptr) {
            cancel();
            return;
          }
          inner->addOnResolvedListener([conn, cancel](const std::optional<std::vector<std::string>>& answers) {
            if (!answers.has_value()) {
              cancel();
              return;
            }
            std::vector<const char*> ptrs;
            ptrs.reserve(answers->size());
            for (const auto& a : *answers) ptrs.push_back(a.c_str());
            rnssh_connection_respond_kbi(conn, ptrs.data(), ptrs.size());
          });
          inner->addOnRejectedListener([cancel](const std::exception_ptr&) { cancel(); });
        });
    outer->addOnRejectedListener([cancel](const std::exception_ptr&) { cancel(); });
  } catch (...) {
    cancel();
  }
}

void onConnected(void* user, uint64_t conn, const RnsshHostKey* key) {
  auto* ctx = static_cast<ConnectionContext*>(user);
  auto promise = std::move(ctx->connectPromise);
  ctx->connectPromise = nullptr;
  if (promise == nullptr) return;
  promise->resolve(std::make_shared<HybridSshConnection>(conn, ctx->host, ctx->port, ctx->username, toHostKey(key)));
}

void onError(void* user, uint64_t /*conn*/, RnsshCode code, const char* message) {
  auto* ctx = static_cast<ConnectionContext*>(user);
  auto promise = std::move(ctx->connectPromise);
  ctx->connectPromise = nullptr;
  if (promise == nullptr) return;
  promise->reject(makeError(code, message));
}

void onDisconnected(void* user, uint64_t /*conn*/, const char* reason) {
  auto* ctx = static_cast<ConnectionContext*>(user);
  if (ctx->handlers.onDisconnected.has_value()) {
    (*ctx->handlers.onDisconnected)(str(reason));
  }
}

void release(void* user) {
  delete static_cast<ConnectionContext*>(user);
}

} // namespace

RnsshConnectionCallbacks ConnectionContext::callbacks(ConnectionContext* ctx) {
  RnsshConnectionCallbacks c;
  c.user = ctx;
  c.on_host_key = &onHostKey;
  // A NULL pointer tells Rust "no handler": password auth then answers
  // keyboard-interactive prompts itself, and explicit KBI auth is refused.
  c.on_keyboard_interactive = ctx->handlers.onKeyboardInteractive.has_value() ? &onKeyboardInteractive : nullptr;
  c.on_connected = &onConnected;
  c.on_error = &onError;
  c.on_disconnected = &onDisconnected;
  c.release = &release;
  return c;
}

} // namespace margelo::nitro::ssh
