// Resolve the package from the monorepo root so the example always runs the
// working-tree sources.
const path = require('node:path')
const { getDefaultConfig } = require('expo/metro-config')

const root = path.resolve(__dirname, '..')
const config = getDefaultConfig(__dirname)
config.watchFolders = [root]
config.resolver.nodeModulesPaths = [path.join(__dirname, 'node_modules'), path.join(root, 'node_modules')]
config.resolver.disableHierarchicalLookup = true
module.exports = config
