// Register the package under development (symlinked into node_modules by
// scripts/link-package.js) with Expo / React Native autolinking. It is not a
// package.json dependency, so the dependency scanner would not find it otherwise.
const path = require('node:path')

module.exports = {
  dependencies: {
    '@osuki-dev/react-native-ssh': {
      root: path.resolve(__dirname, '..'),
    },
  },
}
