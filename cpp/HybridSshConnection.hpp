#pragma once

#include "HybridSshConnectionSpec.hpp"
#include "rnssh.h"
#include "SshConnectionHandlers.hpp"
#include "SshHostKey.hpp"
#include <cstdint>
#include <memory>
#include <string>

namespace margelo::nitro::ssh {

class HybridSshConnection : public HybridSshConnectionSpec {
public:
  HybridSshConnection(uint64_t id, std::string host, double port, std::string username, SshHostKey hostKey)
      : HybridObject(TAG), _id(id), _host(std::move(host)), _port(port), _username(std::move(username)),
        _hostKey(std::move(hostKey)) {}
  ~HybridSshConnection() override = default;

  double getId() override { return static_cast<double>(_id); }
  bool getIsConnected() override;
  std::string getHost() override { return _host; }
  double getPort() override { return _port; }
  std::string getUsername() override { return _username; }
  SshHostKey getHostKey() override { return _hostKey; }

  std::shared_ptr<Promise<std::shared_ptr<HybridSshShellSpec>>> openShell(const SshShellOptionsSpec& options,
                                                                         const SshShellHandlers& handlers) override;
  std::shared_ptr<Promise<SshExecResult>> exec(const std::string& command) override;
  std::shared_ptr<Promise<SshExecTextResult>> execText(const std::string& command) override;
  std::shared_ptr<Promise<std::shared_ptr<HybridSshLocalForwardSpec>>> forwardLocal(const SshForwardOptionsSpec& options,
                                                                                  const SshForwardHandlers& handlers) override;
  std::shared_ptr<Promise<void>> disconnect() override;

private:
  uint64_t _id;
  std::string _host;
  double _port;
  std::string _username;
  SshHostKey _hostKey;
};

/**
 * Heap context owned by Rust for the lifetime of the connection (freed via
 * `release`). Carries the JS handlers plus, until connect finishes, the
 * promise that produces the `HybridSshConnection`.
 */
struct ConnectionContext {
  SshConnectionHandlers handlers;
  std::shared_ptr<Promise<std::shared_ptr<HybridSshConnectionSpec>>> connectPromise;
  std::string host;
  double port = 22;
  std::string username;

  static RnsshConnectionCallbacks callbacks(ConnectionContext* ctx);
};

} // namespace margelo::nitro::ssh
