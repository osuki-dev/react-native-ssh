#include "HybridSshShell.hpp"
#include "RnsshBridge.hpp"
#include "rnssh.h"

namespace margelo::nitro::ssh {

using namespace bridge;

namespace {
/// Rust reports NOT_FOUND once a shell left the registry; for JS that simply
/// means "closed".
void throwIfFailed(RnsshCode code, const char* what) {
  if (code == RNSSH_OK) return;
  if (code == 2 /* NOT_FOUND */) code = 8 /* CLOSED */;
  throw SshNativeError(code, what);
}
} // namespace

bool HybridSshShell::getIsOpen() {
  return rnssh_shell_is_open(_id);
}

void HybridSshShell::write(const std::shared_ptr<ArrayBuffer>& data) {
  if (data == nullptr || data->size() == 0) return;
  // JS-owned buffers are only valid on the JS thread, which is where we are:
  // Rust copies the bytes before returning.
  throwIfFailed(rnssh_shell_write(_id, data->data(), data->size()), "shell.write");
}

void HybridSshShell::writeString(const std::string& data) {
  if (data.empty()) return;
  throwIfFailed(rnssh_shell_write(_id, reinterpret_cast<const uint8_t*>(data.data()), data.size()), "shell.writeString");
}

void HybridSshShell::resize(double cols, double rows, double widthPx, double heightPx) {
  auto u = [](double v) { return v > 0 ? static_cast<uint32_t>(v) : 0u; };
  throwIfFailed(rnssh_shell_resize(_id, u(cols), u(rows), u(widthPx), u(heightPx)), "shell.resize");
}

void HybridSshShell::sendEof() {
  throwIfFailed(rnssh_shell_send_eof(_id), "shell.sendEof");
}

std::shared_ptr<Promise<void>> HybridSshShell::close() {
  auto promise = Promise<void>::create();
  rnssh_shell_close(_id, VoidCompletion::make(promise));
  return promise;
}

// ---------------------------------------------------------------------------
// ShellContext — Rust → JS event plumbing
// ---------------------------------------------------------------------------

namespace {

void onData(void* user, uint64_t /*shell*/, uint32_t stream, uint8_t* data, size_t len, size_t cap) {
  auto* ctx = static_cast<ShellContext*>(user);
  auto buffer = adoptRustBytes(data, len, cap);
  if (stream == 1 && ctx->handlers.onStderr.has_value()) {
    (*ctx->handlers.onStderr)(buffer);
  } else {
    ctx->handlers.onData(buffer);
  }
}

void onClosed(void* user, uint64_t /*shell*/, bool hasExitCode, uint32_t exitCode) {
  auto* ctx = static_cast<ShellContext*>(user);
  ctx->handlers.onClosed(hasExitCode ? std::optional<double>(static_cast<double>(exitCode)) : std::nullopt);
}

void release(void* user) {
  delete static_cast<ShellContext*>(user);
}

void onOpened(void* user, uint64_t shell, RnsshCode code, const char* message) {
  auto* ctx = static_cast<ShellContext*>(user);
  auto promise = std::move(ctx->openPromise);
  ctx->openPromise = nullptr;
  if (promise == nullptr) return;
  if (code == RNSSH_OK) {
    promise->resolve(std::make_shared<HybridSshShell>(shell));
  } else {
    promise->reject(makeError(code, message));
  }
  // On failure Rust calls `release` right after this; on success the context
  // lives until the shell closes.
}

} // namespace

RnsshShellCallbacks ShellContext::callbacks(ShellContext* ctx) {
  RnsshShellCallbacks c;
  c.user = ctx;
  c.on_opened = &onOpened;
  c.on_data = &onData;
  c.on_closed = &onClosed;
  c.release = &release;
  return c;
}


} // namespace margelo::nitro::ssh
