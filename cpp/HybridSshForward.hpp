#pragma once

#include "HybridSshLocalForwardSpec.hpp"
#include "SshForwardHandlers.hpp"
#include "rnssh.h"
#include <cstdint>
#include <memory>

namespace margelo::nitro::ssh {

/**
 * JS-facing handle to a local port forward. State lives in Rust (keyed by
 * `id`); after the forward closed, `isOpen` is false and `close()` is a no-op.
 */
class HybridSshForward : public HybridSshLocalForwardSpec {
public:
  HybridSshForward(uint64_t id, uint16_t localPort) : HybridObject(TAG), _id(id), _localPort(localPort) {}
  ~HybridSshForward() override = default;

  double getId() override { return static_cast<double>(_id); }
  double getLocalPort() override { return static_cast<double>(_localPort); }
  bool getIsOpen() override;
  double getActiveConnections() override;
  std::shared_ptr<Promise<void>> close() override;

private:
  uint64_t _id;
  uint16_t _localPort;
};

/**
 * Heap context owned by Rust for the lifetime of the forward (freed via
 * `release`). Holds the JS handlers and, until `on_opened` fires, the promise
 * that produces the `HybridSshForward`.
 */
struct ForwardContext {
  SshForwardHandlers handlers;
  std::shared_ptr<Promise<std::shared_ptr<HybridSshLocalForwardSpec>>> openPromise;

  static RnsshForwardCallbacks callbacks(ForwardContext* ctx);
};

} // namespace margelo::nitro::ssh
