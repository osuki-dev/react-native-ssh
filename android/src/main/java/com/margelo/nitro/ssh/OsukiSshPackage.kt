package com.margelo.nitro.ssh

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfoProvider

/**
 * Loads libOsukiSsh.so so Nitro can register the C++ HybridObjects.
 * There are no Java/Kotlin native modules in this package.
 */
class OsukiSshPackage : BaseReactPackage() {
  override fun getModule(name: String, reactContext: ReactApplicationContext): NativeModule? = null

  override fun getReactModuleInfoProvider(): ReactModuleInfoProvider = ReactModuleInfoProvider { HashMap() }

  companion object {
    init {
      OsukiSshOnLoad.initializeNative()
    }
  }
}
