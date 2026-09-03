#include "HybridSshForward.hpp"
#include "RnsshBridge.hpp"

namespace margelo::nitro::ssh {

using namespace bridge;

bool HybridSshForward::getIsOpen() {
  return rnssh_forward_is_open(_id);
}

double HybridSshForward::getActiveConnections() {
  return static_cast<double>(rnssh_forward_active_connections(_id));
}

std::shared_ptr<Promise<void>> HybridSshForward::close() {
  auto promise = Promise<void>::create();
  rnssh_forward_close(_id, VoidCompletion::make(promise));
  return promise;
}

namespace {

void onOpened(void* user, uint64_t forward, RnsshCode code, const char* message, uint16_t localPort) {
  auto* ctx = static_cast<ForwardContext*>(user);
  auto promise = std::move(ctx->openPromise);
  ctx->openPromise = nullptr;
  if (promise == nullptr) return;
  if (code == RNSSH_OK) {
    promise->resolve(std::make_shared<HybridSshForward>(forward, localPort));
  } else {
    promise->reject(makeError(code, message));
  }
}

void onClosed(void* user, uint64_t /*forward*/, const char* reason) {
  auto* ctx = static_cast<ForwardContext*>(user);
  ctx->handlers.onClosed(reason != nullptr ? std::optional<std::string>(str(reason)) : std::nullopt);
}

void release(void* user) {
  delete static_cast<ForwardContext*>(user);
}

} // namespace

RnsshForwardCallbacks ForwardContext::callbacks(ForwardContext* ctx) {
  RnsshForwardCallbacks c;
  c.user = ctx;
  c.on_opened = &onOpened;
  c.on_closed = &onClosed;
  c.release = &release;
  return c;
}

} // namespace margelo::nitro::ssh
