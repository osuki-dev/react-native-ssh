// Symlinks the package under development into example/node_modules so Metro,
// TypeScript and Expo autolinking all see the working tree (bun's `file:` would
// copy it, `link:` points at the global store).
const fs = require('node:fs')
const path = require('node:path')

const scope = path.join(__dirname, '..', 'node_modules', '@osuki-dev')
const target = path.join(scope, 'react-native-ssh')
fs.rmSync(target, { recursive: true, force: true })
fs.mkdirSync(scope, { recursive: true })
fs.symlinkSync(path.join('..', '..', '..'), target, 'dir')
console.log(`linked ${target} -> ${fs.realpathSync(target)}`)
