#pragma once

#include "HybridSshClientSpec.hpp"

namespace margelo::nitro::ssh {

/**
 * Entry point registered with Nitro as `SshClient` (see nitro.json).
 * Stateless: every connection is its own HybridObject.
 */
class HybridSshClient : public HybridSshClientSpec {
public:
  HybridSshClient() : HybridObject(TAG) {}
  ~HybridSshClient() override = default;

  std::string getVersion() override;

  std::shared_ptr<Promise<std::shared_ptr<HybridSshConnectionSpec>>> connect(const SshConnectOptionsSpec& options,
                                                                            const SshConnectionHandlers& handlers) override;
  void cancelConnect(double id) override;
  std::shared_ptr<Promise<SshKeyPair>> generateKeyPair(SshKeyType type, const std::optional<std::string>& comment,
                                                       const std::optional<std::string>& passphrase) override;
  SshKeyInfo inspectPrivateKey(const std::string& privateKey, const std::optional<std::string>& passphrase) override;
};

} // namespace margelo::nitro::ssh
