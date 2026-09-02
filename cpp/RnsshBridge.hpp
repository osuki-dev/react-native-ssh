//
// RnsshBridge.hpp — small helpers shared by the Hybrid* implementations.
//
// The Rust side (rust/rnssh-ffi, header cpp/rnssh.h) talks in C: NUL-terminated
// strings, numeric error codes, `void* user` contexts. Everything in here
// converts between that world and Nitro's C++ types.
//
#pragma once

#include "rnssh.h"
#include "SshHostKey.hpp"
#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Promise.hpp>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace margelo::nitro::ssh::bridge {

/// Stable names for `rnssh-core::ErrorCode`. Keep in sync with rust/rnssh-core/src/error.rs.
inline const char* errorCodeName(RnsshCode code) {
  switch (code) {
    case 0: return "OK";
    case 1: return "INVALID_ARGUMENT";
    case 2: return "NOT_FOUND";
    case 3: return "CONNECT";
    case 4: return "TIMEOUT";
    case 5: return "HOST_KEY_REJECTED";
    case 6: return "AUTH_FAILED";
    case 7: return "KEY";
    case 8: return "CLOSED";
    case 9: return "PROTOCOL";
    case 10: return "IO";
    case 11: return "CANCELLED";
    case 12: return "INTERNAL";
    case 13: return "QUEUE_FULL";
    case 14: return "TOO_LARGE";
    default: return "INTERNAL";
  }
}

/// Errors cross into JS as `Error` objects whose message is
/// `RNSSH_<CODE>: <detail>`. `src/errors.ts` parses that prefix back into a
/// typed `SshError` with a `.code` property.
class SshNativeError : public std::runtime_error {
public:
  SshNativeError(RnsshCode code, const std::string& detail)
      : std::runtime_error(std::string("RNSSH_") + errorCodeName(code) + ": " + detail), _code(code) {}
  RnsshCode code() const { return _code; }

private:
  RnsshCode _code;
};

inline std::exception_ptr makeError(RnsshCode code, const char* message) {
  return std::make_exception_ptr(SshNativeError(code, message != nullptr ? message : errorCodeName(code)));
}

inline std::exception_ptr makeError(RnsshCode code, const std::string& message) {
  return makeError(code, message.c_str());
}

inline std::string str(const char* s) {
  return s != nullptr ? std::string(s) : std::string();
}

inline const char* cstrOrNull(const std::optional<std::string>& s) {
  return s.has_value() ? s->c_str() : nullptr;
}

inline SshHostKey toHostKey(const RnsshHostKey* key) {
  if (key == nullptr) return SshHostKey("", "", "");
  return SshHostKey(str(key->algorithm), str(key->fingerprint), str(key->public_key));
}

/// Takes ownership of a Rust `Vec<u8>` (ptr/len/cap) and exposes it to JS
/// without copying. The deleter hands the allocation back to Rust.
inline std::shared_ptr<ArrayBuffer> adoptRustBytes(uint8_t* ptr, size_t len, size_t cap) {
  if (ptr == nullptr || len == 0) {
    if (ptr != nullptr) rnssh_bytes_free(ptr, len, cap);
    return ArrayBuffer::copy(std::vector<uint8_t>{});
  }
  return ArrayBuffer::wrap(ptr, len, [ptr, len, cap]() { rnssh_bytes_free(ptr, len, cap); });
}

inline std::shared_ptr<ArrayBuffer> copyBytes(const uint8_t* ptr, size_t len) {
  if (ptr == nullptr || len == 0) return ArrayBuffer::copy(std::vector<uint8_t>{});
  return ArrayBuffer::copy(ptr, len);
}

/// Lossy UTF-8 → UTF-8: every invalid sequence becomes U+FFFD so the string
/// can be handed to the JS runtime safely (Hermes rejects malformed input).
inline std::string sanitizeUtf8(const uint8_t* data, size_t len) {
  std::string out;
  out.reserve(len);
  size_t i = 0;
  auto replacement = [&out]() { out.append("\xEF\xBF\xBD"); };
  while (i < len) {
    uint8_t c = data[i];
    if (c < 0x80) {
      out.push_back(static_cast<char>(c));
      i++;
      continue;
    }
    size_t need = 0;
    uint32_t cp = 0;
    if ((c & 0xE0) == 0xC0 && c >= 0xC2) { need = 1; cp = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { need = 2; cp = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07; }
    else { replacement(); i++; continue; }
    if (i + need >= len) { replacement(); i++; continue; }
    bool ok = true;
    for (size_t k = 1; k <= need; k++) {
      uint8_t cc = data[i + k];
      if ((cc & 0xC0) != 0x80) { ok = false; break; }
      cp = (cp << 6) | (cc & 0x3F);
    }
    if (ok) {
      // Reject overlongs, surrogates and out-of-range code points.
      if ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10FFFF)) || (cp >= 0xD800 && cp <= 0xDFFF)) ok = false;
    }
    if (!ok) { replacement(); i++; continue; }
    out.append(reinterpret_cast<const char*>(data + i), need + 1);
    i += need + 1;
  }
  return out;
}

/// Heap context for one-shot `RnsshCompletion` callbacks resolving a `Promise<void>`.
struct VoidCompletion {
  std::shared_ptr<Promise<void>> promise;

  static RnsshCompletion make(std::shared_ptr<Promise<void>> promise) {
    auto* ctx = new VoidCompletion{std::move(promise)};
    RnsshCompletion c;
    c.user = ctx;
    c.on_complete = &VoidCompletion::onComplete;
    return c;
  }

private:
  static void onComplete(void* user, RnsshCode code, const char* message) {
    std::unique_ptr<VoidCompletion> ctx(static_cast<VoidCompletion*>(user));
    if (code == RNSSH_OK) {
      ctx->promise->resolve();
    } else {
      ctx->promise->reject(makeError(code, message));
    }
  }
};

} // namespace margelo::nitro::ssh::bridge
