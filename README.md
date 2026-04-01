# npm-supply-chain-check
A simple node.js CLI tool for checking for npm supply-chain risks.

Give it an npm package name and optionally a starting folder (or "global") and it reports all uses of that package.

## Running

```
npx npm-supply-chain-check <package-name> [starting-folder]
```

If you don't specify a starting folder, it will check the current working directory. You can also specify "global" to check globally installed packages.

### Example

```
npx npm-supply-chain-check left-pad
```
