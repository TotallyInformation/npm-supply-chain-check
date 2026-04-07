#!/usr/bin/env node
// @ts-nocheck
/** check-supply-chain.mjs - Supply-chain risk checker for npm package dependencies.
 *
 * Searches a directory tree for npm project roots and reports which packages
 * depend on a specified npm package, along with what versions are installed.
 * Designed to quickly assess potential supply-chain compromises (e.g. Axios-style
 * attacks) across all local projects.
 *
 * Usage:
 *   node check-supply-chain.mjs <package-name> [start-folder|"global"]
 *
 * Arguments:
 *   package-name   The npm package name to search for (e.g. axios)
 *   start-folder   Directory to search from (default: current working directory)
 *                  Use "global" to check globally installed packages instead.
 *
 * @example
 *   node bin/check-supply-chain.mjs axios
 *   node bin/check-supply-chain.mjs axios /home/user/projects
 *   node bin/check-supply-chain.mjs axios global
 *
 * @module check-supply-chain
 */

import { readdir, readFile, stat } from 'node:fs/promises'
import { join, resolve, relative } from 'node:path'
import { exec } from 'node:child_process'
import { promisify } from 'node:util'
import process from 'node:process'

const execAsync = promisify(exec)

// ── Argument parsing ──────────────────────────────────────────────────────────

const [,, targetPkg, startArg = '.'] = process.argv

/**
 * Read and print this CLI package version from package.json.
 *
 * @returns {Promise<void>}
 */
async function printCliVersion() {
    try {
        const pkgJsonUrl = new URL('./package.json', import.meta.url)
        const pkg = JSON.parse(await readFile(pkgJsonUrl, 'utf8'))
        console.log(pkg.version ?? 'unknown')
        process.exit(0)
    } catch {
        console.error('\n  ERROR: Could not read package version from package.json.')
        process.exit(1)
    }
}

/** Validate the package name against npm's allowed character set.
 * Scoped: @scope/name — Unscoped: name
 * Only allows: lowercase letters, digits, hyphens, underscores, dots, @, /
 * This prevents shell injection when shell:true is used on Windows.
 * @type {RegExp}
 */
const NPM_PKG_RE = /^(@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i

if (targetPkg === '--version' || targetPkg === '-v') {
    await printCliVersion()
}

if (!targetPkg || targetPkg === '--help' || targetPkg === '-h') {
    console.log(`
Supply-Chain Dependency Checker
================================
Usage:  check-supply-chain <package-name> [start-folder|"global"]

Options:
    -h, --help      Show this help message
    -v, --version   Print CLI version

Arguments:
  package-name   The npm package name to search for (e.g. axios)
  start-folder   Directory to search from (default: current directory)
                 Use "global" to check globally installed packages

Examples:
  node check-supply-chain.mjs axios
  node check-supply-chain.mjs axios /home/user/projects
  node check-supply-chain.mjs axios global
`)
    process.exit(targetPkg ? 0 : 1)
}

if (!NPM_PKG_RE.test(targetPkg)) {
    console.error(`\n  ERROR: "${targetPkg}" is not a valid npm package name.`)
    console.error('  Package names may only contain: letters, digits, hyphens, underscores, dots, and an optional @scope/ prefix.')
    process.exit(1)
}

const isGlobal = startArg.toLowerCase() === 'global'
const startFolder = isGlobal ? null : resolve(startArg)

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Find all npm project roots within a directory tree. A project root is a
 * directory that contains both a `package.json` file and a `node_modules`
 * directory. Skips `node_modules` directories and hidden directories (those
 * starting with `.`) to avoid false positives and infinite recursion.
 *
 * @param {string} dir - Absolute path of the directory to search recursively
 * @returns {Promise<string[]>} Absolute paths of all project roots found
 */
async function findProjectRoots(dir) {
    const roots = []
    let entries

    try {
        entries = await readdir(dir, { withFileTypes: true })
    } catch {
        return roots
    }

    const hasPackageJson = entries.some(e => e.isFile() && e.name === 'package.json')
    const hasNodeModules = entries.some(e => e.isDirectory() && e.name === 'node_modules')

    if (hasPackageJson && hasNodeModules) {
        roots.push(dir)
        // Still recurse: mono-repos can have nested project roots with their own node_modules
    }

    for (const entry of entries) {
        if (!entry.isDirectory()) continue
        // Skip node_modules and hidden directories (e.g. .git, .cache, .npm)
        if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue

        const childRoots = await findProjectRoots(join(dir, entry.name))
        roots.push(...childRoots)
    }

    return roots
}

/**
 * Run `npm ls <targetPkg> --all --json` via the shell and return the parsed
 * JSON output. Only used for the --global mode (local projects use the
 * lock-file parser instead, which is faster and more reliable).
 *
 * Uses `exec()` (shell-based) so that npm works on Windows, where it is a
 * batch file (.cmd) that cannot be launched with execFile without a shell.
 * Safe because `targetPkg` is validated against npm's character set before
 * reaching here — none of those characters are shell metacharacters.
 *
 * @param {string|null} cwd - Working directory; null when using --global
 * @param {boolean} [global=false] - Whether to pass the --global flag
 * @returns {Promise<object|null>} Parsed npm ls JSON tree, or null on failure
 */
async function runNpmLs(cwd, global = false) {
    const globalFlag = global ? ' --global' : ''
    const cmd = `npm ls "${targetPkg}" --all --json${globalFlag}`

    try {
        const { stdout } = await execAsync(cmd, {
            cwd: cwd ?? undefined,
            env: process.env,
            timeout: 60_000,
            maxBuffer: 50 * 1024 * 1024,
        })
        return JSON.parse(stdout)
    } catch (err) {
        // npm ls exits 1 for missing peer deps but stdout is still valid JSON
        if (err.stdout) {
            try { return JSON.parse(err.stdout) } catch { /* fall through */ }
        }
        return null
    }
}

/**
 * Normalise a lock-file package path to POSIX separators so comparisons are
 * consistent across platforms.
 *
 * @param {string} lockPath - Raw package path key from package-lock.json
 * @returns {string} Normalised path using forward slashes
 */
function normalizeLockPath(lockPath) {
    return String(lockPath).replace(/\\/g, '/')
}

/**
 * Detect whether local/link/workspace dependencies are present.
 *
 * @param {object|null} lock - Parsed lock file object
 * @param {object|null} rootPkgJson - Parsed root package.json
 * @returns {boolean} True when npm ls fallback should be considered
 */
function mayNeedTreeFallback(lock, rootPkgJson) {
    const pkgSections = [
        rootPkgJson?.dependencies,
        rootPkgJson?.devDependencies,
        rootPkgJson?.optionalDependencies,
        rootPkgJson?.peerDependencies,
    ]

    for (const section of pkgSections) {
        if (!section || typeof section !== 'object') continue
        for (const spec of Object.values(section)) {
            if (typeof spec === 'string' && /^(file:|link:|workspace:)/.test(spec)) {
                return true
            }
        }
    }

    const lockPkgs = lock?.packages
    if (!lockPkgs || typeof lockPkgs !== 'object') return false

    for (const data of Object.values(lockPkgs)) {
        if (!data || typeof data !== 'object') continue
        if (data.link === true) return true
        if (typeof data.resolved === 'string' && /^(file:|link:|workspace:)/.test(data.resolved)) {
            return true
        }
    }

    return false
}

/**
 * @typedef {object} LockFinding
 * @property {string}   version    - Installed version of targetPkg
 * @property {string}   installedAt - node_modules path key from the lock file
 * @property {string[]} dependents  - Package names that declare targetPkg as a dependency
 * @property {boolean}  isDirect    - True when the project root itself declares the dep
 */

/**
 * Analyse a v2/v3 package-lock.json (npm 7+) flat packages map for all
 * installed instances of `targetPkg` and collect the packages that depend
 * on each instance.
 *
 * Lock-file format (v2/v3):
 *   packages[""] = project root
 *   packages["node_modules/foo"] = installed package foo
 *   packages["node_modules/bar/node_modules/foo"] = nested install of foo inside bar
 *
 * @param {object} lock - Parsed package-lock.json object
 * @param {object|null} [rootPkgJson=null] - Parsed package.json for the project root.
 *   When provided (e.g. when using node_modules/.package-lock.json which lacks
 *   the root `""` entry) it is used to detect direct dependencies.
 * @returns {LockFinding[]} One entry per installed instance of targetPkg
 */
function analyseLockFile(lock, rootPkgJson = null) {
    const pkgs = lock.packages
    if (!pkgs || typeof pkgs !== 'object') return []

    // Suffix patterns that identify an installed instance of targetPkg.
    // Both slash styles handled for cross-platform lock files.
    const suffix = `node_modules/${targetPkg}`

    /** @type {Map<string, LockFinding>} keyed by the lock-file path */
    const instances = new Map()

    for (const [rawPath, data] of Object.entries(pkgs)) {
        const path = normalizeLockPath(rawPath)
        if (path === suffix || path.endsWith(`/${suffix}`)) {
            instances.set(path, {
                version: data.version ?? 'unknown',
                installedAt: path,
                dependents: [],
                isDirect: false,
            })
        }
    }

    if (instances.size === 0) return []

    // Walk all packages to find which ones declare targetPkg in their deps
    for (const [rawPath, data] of Object.entries(pkgs)) {
        const path = normalizeLockPath(rawPath)
        const allDeps = Object.assign(
            {},
            data.dependencies,
            data.devDependencies,
            data.optionalDependencies,
            data.peerDependencies,
        )
        if (!(targetPkg in allDeps)) continue

        const isRoot = path === ''
        // Derive the declaring package's display name
        const declarer = isRoot
            ? '(project root / direct dependency)'
            : path.replace(/^.*node_modules\//, '')

        // Attribute the dependent to the closest applicable instance.
        // Instances nested inside the same parent path take priority.
        let bestMatch = null
        let bestLen = -1
        for (const [instPath] of instances) {
            const parentOfInst = instPath === suffix
                ? ''
                : instPath.slice(0, instPath.length - suffix.length - 1)
            const matchBase = path === '' ? '' : path
            if (matchBase.startsWith(parentOfInst) && parentOfInst.length > bestLen) {
                bestMatch = instPath
                bestLen = parentOfInst.length
            }
        }
        // Fall back to the top-level instance if no nested match
        if (!bestMatch) bestMatch = `node_modules/${targetPkg}`

        const inst = instances.get(bestMatch)
        if (inst) {
            if (isRoot) inst.isDirect = true
            if (!inst.dependents.includes(declarer)) inst.dependents.push(declarer)
        }
    }

    // Supplement: when using node_modules/.package-lock.json (no root "" entry),
    // cross-reference the project's package.json to detect direct dependencies.
    if (rootPkgJson) {
        const rootAllDeps = Object.assign(
            {},
            rootPkgJson.dependencies,
            rootPkgJson.devDependencies,
            rootPkgJson.optionalDependencies,
            rootPkgJson.peerDependencies,
        )
        if (targetPkg in rootAllDeps) {
            const topKey = `node_modules/${targetPkg}`
            const topInst = instances.get(topKey)
            if (topInst && !topInst.isDirect) {
                topInst.isDirect = true
                const label = '(project root / direct dependency)'
                if (!topInst.dependents.includes(label)) topInst.dependents.unshift(label)
            }
        }
    }

    return [...instances.values()]
}

/**
 * @typedef {object} DependencyFinding
 * @property {string[]} chain  - Package names forming the dependency chain leading to targetPkg
 * @property {string}   version    - Installed version of targetPkg at this node
 * @property {boolean}  deduped    - True when npm has hoisted/deduped this instance
 * @property {boolean}  overridden - True when an npm override has altered this instance
 */

/**
 * Recursively walk an npm ls JSON dependency tree and collect every occurrence
 * of `targetPkg`, recording the dependency chain that leads to each one.
 * Used only for the global npm ls output (which has no lock file).
 *
 * @param {object}   node      - Current tree node from the npm ls JSON output
 * @param {string[]} [chain=[]] - Package names of ancestors leading to this node
 * @returns {DependencyFinding[]} All occurrences of targetPkg under this node
 */
function collectFindingsFromTree(node, chain = []) {
    if (!node.dependencies) return []
    const results = []

    for (const [name, data] of Object.entries(node.dependencies)) {
        if (name === targetPkg) {
            results.push({
                chain,
                version: data.version ?? 'unknown',
                deduped: data.deduped === true,
                overridden: data.overridden === true,
            })
        }
        results.push(...collectFindingsFromTree(data, [...chain, name]))
    }

    return results
}

// ── Formatting ────────────────────────────────────────────────────────────────

const W = 70 // display width
const RULE = '─'.repeat(W)
const DOUBLE_RULE = '═'.repeat(W)

/**
 * Attempt to read and parse a lock file from the given project root.
 * Tries `package-lock.json`, `npm-shrinkwrap.json`, and finally the hidden
 * `node_modules/.package-lock.json` that npm v7+ always writes.
 *
 * @param {string} root - Absolute path to the project root directory
 * @returns {Promise<object|null>} Parsed lock file object, or null if unavailable
 */
async function readLockFile(root) {
    for (const name of ['package-lock.json', 'npm-shrinkwrap.json', 'node_modules/.package-lock.json']) {
        try {
            return JSON.parse(await readFile(join(root, name), 'utf8'))
        } catch { /* try next */ }
    }
    return null
}

/**
 * Read and parse the project's package.json.
 *
 * @param {string} root - Absolute path to the project root directory
 * @returns {Promise<object|null>} Parsed package.json, or null if unreadable
 */
async function readPackageJson(root) {
    try {
        return JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
    } catch {
        return null
    }
}

/**
 * Print a lock-file based report for a single local project.
 *
 * @param {string}        projectName - Display name of the project
 * @param {string}        projectPath - Absolute filesystem path of the project root
 * @param {string}        relPath     - Path relative to startFolder
 * @param {LockFinding[]} findings    - Pre-computed findings from analyseLockFile()
 */
function printLockReport(projectName, projectPath, relPath, findings) {
    console.log(`\n${RULE}`)
    console.log(`Project : ${projectName}`)
    if (relPath) console.log(`Rel path: ${relPath}`)
    console.log(`Path    : ${projectPath}`)
    console.log(RULE)

    if (findings.length === 0) {
        console.log(`  (not found — "${targetPkg}" is not in this project's lock file)`)
        return
    }

    const plural = findings.length === 1 ? 'instance' : 'instances'
    console.log(`  *** FOUND: ${findings.length} installed ${plural} of "${targetPkg}" ***\n`)

    for (const f of findings) {
        const location = f.installedAt === `node_modules/${targetPkg}`
            ? 'top-level (hoisted)'
            : `nested — ${f.installedAt}`
        console.log(`  Installed version : ${f.version}`)
        console.log(`  Location          : ${location}`)
        if (f.isDirect) {
            console.log(`  Direct dependency : yes`)
        }
        if (f.dependents.length > 0) {
            console.log(`  Depended on by    :`)
            for (const d of f.dependents) {
                console.log(`    • ${d}`)
            }
        } else {
            console.log(`  Depended on by    : (no dependents recorded in lock file)`)
        }
        console.log()
    }
}

/**
 * Print a global npm ls tree-based report.
 *
 * @param {DependencyFinding[]} findings - From collectFindingsFromTree()
 */
function printGlobalReport(findings) {
    console.log(`\n${RULE}`)
    console.log(`Scope : Global npm packages`)
    console.log(RULE)

    if (findings.length === 0) {
        console.log(`  (not found — "${targetPkg}" is not in the global npm dependency tree)`)
        return
    }

    /** @type {Map<string, DependencyFinding[]>} */
    const byVersion = new Map()
    for (const f of findings) {
        const list = byVersion.get(f.version) ?? []
        list.push(f)
        byVersion.set(f.version, list)
    }

    const plural = findings.length === 1 ? 'place' : 'places'
    console.log(`  *** FOUND: "${targetPkg}" appears in ${findings.length} ${plural} ***\n`)

    for (const [version, instances] of byVersion) {
        console.log(`  Installed version: ${version}`)
        for (const inst of instances) {
            const depPath = inst.chain.length > 0
                ? inst.chain.join(' → ') + ` → ${targetPkg}`
                : `${targetPkg}  (direct global dependency)`
            const flags = [
                inst.deduped && '(deduped)',
                inst.overridden && '(overridden)',
            ].filter(Boolean)
            const flagStr = flags.length > 0 ? `  ${flags.join(' ')}` : ''
            console.log(`    • ${depPath}${flagStr}`)
        }
        console.log()
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

console.log(`\n${DOUBLE_RULE}`)
console.log('Supply-Chain Dependency Checker')
console.log(DOUBLE_RULE)
console.log(`Target  : ${targetPkg}`)
console.log(`Scope   : ${isGlobal ? 'Global npm packages' : startFolder}`)
console.log(DOUBLE_RULE)

if (isGlobal) {
    // ── Global mode: use npm ls (no lock file for global installs) ────────────
    console.log('\nQuerying global npm packages (this may take a moment)...')

    const tree = await runNpmLs(null, true)

    if (!tree) {
        console.error('\n  ERROR: Failed to run "npm ls --global". Is npm available in PATH?')
        process.exit(1)
    }

    const findings = collectFindingsFromTree(tree)
    printGlobalReport(findings)

    console.log(`\n${DOUBLE_RULE}`)
    if (findings.length > 0) {
        console.log(`SUMMARY: "${targetPkg}" IS present in global packages — review versions above.`)
        console.log(`\n  *** Check the package's changelog and known CVEs immediately. ***`)
    } else {
        console.log(`SUMMARY: "${targetPkg}" was NOT found in global packages.`)
    }
} else {
    // ── Local folder mode: read lock files directly (fast, no subprocess) ─────

    try {
        const s = await stat(startFolder)
        if (!s.isDirectory()) {
            console.error(`\n  ERROR: "${startFolder}" is not a directory.`)
            process.exit(1)
        }
    } catch {
        console.error(`\n  ERROR: Start folder "${startFolder}" does not exist or is not accessible.`)
        process.exit(1)
    }

    console.log('\nSearching for npm project roots (directories with package.json + node_modules)...')
    const roots = await findProjectRoots(startFolder)

    if (roots.length === 0) {
        console.log('\n  No npm project roots found.')
        console.log('  (A project root requires both a package.json and a node_modules directory)')
        process.exit(0)
    }

    console.log(`Found ${roots.length} project root(s). Analysing lock files...\n`)

    let foundCount = 0
    let noLockCount = 0

    /** @type {Array<{name: string, path: string, relPath: string, findings: LockFinding[], hasLock: boolean}>} */
    const allResults = []

    for (const root of roots) {
        const relPath = relative(startFolder, root) || '.'
        const pkgJson = await readPackageJson(root)
        const projectName = pkgJson?.name ?? relPath

        process.stdout.write(`  Checking ${projectName} ... `)

        const lock = await readLockFile(root)
        if (!lock) {
            console.log('SKIP (no lock file found)')
            noLockCount++
            allResults.push({ name: projectName, path: root, relPath, findings: [], hasLock: false })
            continue
        }

        const lockVer = lock.lockfileVersion ?? 1
        let findings = []

        if (lockVer >= 2 && lock.packages) {
            // v2/v3 lock file — flat packages map (npm 7+)
            // Pass pkgJson so the hidden .package-lock.json case can detect direct deps
            findings = analyseLockFile(lock, pkgJson)

            // Linked/local/workspace installs can hide transitive edges in lock metadata.
            // Fall back to npm ls tree traversal to avoid false negatives.
            if (findings.length === 0 && mayNeedTreeFallback(lock, pkgJson)) {
                process.stdout.write('(linked/local deps detected, using npm ls) ')
                const npmTree = await runNpmLs(root)
                if (npmTree) findings = collectFindingsFromTree(npmTree).map(f => ({
                    version: f.version,
                    installedAt: `node_modules/${targetPkg}`,
                    dependents: f.chain.length > 0 ? [f.chain.join(' → ')] : ['(project root)'],
                    isDirect: f.chain.length === 0,
                }))
            }
        } else {
            // v1 lock file — fall back to npm ls subprocess
            process.stdout.write('(v1 lock, using npm ls) ')
            const npmTree = await runNpmLs(root)
            if (npmTree) findings = collectFindingsFromTree(npmTree).map(f => ({
                version: f.version,
                installedAt: `node_modules/${targetPkg}`,
                dependents: f.chain.length > 0 ? [f.chain.join(' → ')] : ['(project root)'],
                isDirect: f.chain.length === 0,
            }))
        }

        if (findings.length > 0) {
            foundCount++
            console.log(`FOUND (${findings.length} instance${findings.length !== 1 ? 's' : ''})`)
        } else {
            console.log('not found')
        }

        allResults.push({ name: projectName, path: root, relPath, findings, hasLock: true })
    }

    // Detailed reports — only print header for not-found projects, full detail for found
    for (const r of allResults) {
        if (r.hasLock || r.findings.length > 0) {
            printLockReport(r.name, r.path, r.relPath, r.findings)
        }
    }

    const checked = allResults.filter(r => r.hasLock).length
    console.log(`\n${DOUBLE_RULE}`)
    console.log(`SUMMARY`)
    console.log(RULE)
    console.log(`  Projects scanned      : ${checked}`)
    console.log(`  Skipped (no lock file): ${noLockCount}`)
    console.log(`  "${targetPkg}" found in     : ${foundCount} project(s)`)
    if (foundCount > 0) {
        console.log(`\n  *** Review the dependency details above for version risks.    ***`)
        console.log(`  *** Check the package's changelog and known CVEs immediately. ***`)
    } else {
        console.log(`\n  No dependency on "${targetPkg}" detected in any scanned project.`)
    }
}

console.log(`${DOUBLE_RULE}\n`)
