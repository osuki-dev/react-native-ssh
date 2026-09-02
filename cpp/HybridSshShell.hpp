#pragma once

#include "HybridSshShellSpec.hpp"
#include "rnssh.h"
#include "SshShellHandlers.hpp"
#include <cstdint>
#include <memory>

namespace margelo::nitro::ssh {

/**
 * JS-facing handle to a running shell. All state lives in Rust (keyed by `id`);
 * this object is a thin, cheap view that stays valid even after the shell
 * closed — calls then throw `RNSSH_CLOSED`.
 */
class HybridSshShell : public HybridSshShellSpec {
public:
  explicit HybridSshShell(uint64_t id) : HybridObject(TAG), _id(id) {}
  ~HybridSshShell() override = default;

  double getId() override { return static_cast<double>(_id); }
  bool getIsOpen() override;

  void write(const std::shared_ptr<ArrayBuffer>& data) override;
  void writeString(const std::string& data) override;
  void resize(double cols, double rows, double widthPx, double heightPx) override;
  void sendEof() override;
  std::shared_ptr<Promise<void>> close() override;

private:
  uint64_t _id;
};

/**
 * Heap context owned by Rust for the lifetime of the shell (freed via the
 * `release` callback). Holds the JS handlers and, until `on_opened` fires,
 * the promise that produces the `HybridSshShell`. Every Rust callback carries
 * the shell id, so nothing here is written after `rnssh_shell_open` returns.
 */
struct ShellContext {
  SshShellHandlers handlers;
  std::shared_ptr<Promise<std::shared_ptr<HybridSshShellSpec>>> openPromise;

  static RnsshShellCallbacks callbacks(ShellContext* ctx);
};

} // namespace margelo::nitro::ssh
