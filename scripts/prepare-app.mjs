#!/usr/bin/env node

// The rack half of install-product.yml, run by the job that holds the secrets (INSTALL_SECRETS_PRIVATE_KEY and
// CONVOX_TOKEN), which runs nothing of the branch being built. It opens the envelope of the variables in memory,
// masks them, creates the Convox app (only if the rack does not list it), waits until it runs, marks it as this
// product's and sets its variables from stdin. No value is written to a file or put on a command line. Its only
// output is the NAMES of the variables it set, for the job that runs the branch's code: that job never receives a
// value. The inputs that need no checkout are checked first, before the rack is touched.
import { spawnSync } from 'node:child_process'
import { appendFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { decryptEnvelope, maskCommands } from './decrypt-secrets.mjs'

export const ENVIRONMENT_NAME = /^[a-z](?:[a-z0-9-]{0,39}[a-z0-9])$/
const PRODUCT_NAME = /^[a-z][a-z0-9-]*$/
const RACK = /^[\w.-]+(\/[\w.-]+)?$/
const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/
const ENV_TYPES = ['dev', 'staging', 'production']
const REPOSITORY = 'atex-products/mytype'

export const CONVOX_LOGIN =
  'test -n "$CONVOX_TOKEN" || { echo "CONVOX_TOKEN is required" >&2; exit 1; }; convox login console.convox.com --token "$CONVOX_TOKEN"'

const fail = (message) => {
  throw new Error(message)
}

const quote = (word) => (/^[\w@%+=:,./-]+$/.test(word) ? word : `'${word.replaceAll("'", "'\\''")}'`)
const words = (...list) => list.map(quote).join(' ')

/** KEY=VALUE lines of the environment file, which holds no secret; blank lines and `#` comments are skipped. */
export const parseEnvFile = (text) =>
  Object.fromEntries(
    text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '' && !line.startsWith('#') && line.includes('='))
      .map((line) => [line.slice(0, line.indexOf('=')).trim(), line.slice(line.indexOf('=') + 1).trim()])
  )

/** The variables of the envelope. An error names a line by its number, never by its text. */
export const parseVariables = (text) =>
  Object.fromEntries(
    text
      .split('\n')
      .map((line, index) => [line, index + 1])
      .map(([line, number]) => {
        if (line.includes('\r')) {
          fail(`VARIABLES line ${number} has a carriage return`)
        }
        return [line, number]
      })
      .filter(([line]) => line.trim() !== '')
      .map(([line, number]) => {
        const at = line.indexOf('=')
        if (!VARIABLE_NAME.test(line.slice(0, at))) {
          fail(`VARIABLES line ${number} is not KEY=VALUE`)
        }
        return [line.slice(0, at), line.slice(at + 1)]
      })
  )

/**
 * App names are rack-wide, so the app is created only when the rack does not list it, and marked
 * INSTALLED_PRODUCT=<product> once it runs. A listed app is the install's own only if it carries that mark: a rerun of
 * a failed install goes on, an app of anyone else (another product, a MyType instance) is refused.
 */
export const createAppLine = ({ rack, app, product }) => {
  const on = (...args) => words('convox', ...args, '--rack', rack)
  const mark = `INSTALLED_PRODUCT=${product}`
  const waitRunning = `{ n=0; until ${on('apps', 'info', app)} | grep -Eq '^Status +running'; do n=$((n+1)); [ "$n" -lt 60 ] || { echo ${quote(`app ${app} is not running`)} >&2; exit 1; }; sleep 10; done; }`
  const refusal = `app ${app} exists on ${rack} and was not created by an install of ${product}`
  return [
    `if ${on('apps')} | awk '{print $1}' | grep -qx ${quote(app)}; then`,
    `${on('env', '--app', app)} | grep -qx ${quote(mark)} || { echo ${quote(refusal)} >&2; exit 1; };`,
    `${waitRunning};`,
    `else ${on('apps', 'create', app)} && ${waitRunning} && printf '%s\\n' ${quote(mark)} | ${on('env', 'set', '--app', app)};`,
    'fi',
  ].join(' ')
}

/** What the inputs say, checked before anything is created: the first thing wrong, or nothing. */
const checkInputs = ({ env, config }) => {
  const { PRODUCT: product = '', ENVIRONMENT: environment = '' } = env
  if (!PRODUCT_NAME.test(product)) {
    fail(`PRODUCT is not a product name: '${product}'`)
  }
  if (!ENVIRONMENT_NAME.test(environment)) {
    fail(
      'ENVIRONMENT starts with a letter, ends with a letter or a digit, and has 2 to 41 lowercase letters, digits or hyphens'
    )
  }
  if (config.TARGET !== 'convox') {
    fail(`TARGET must be convox, got '${config.TARGET ?? ''}'`)
  }
  if (!RACK.test(config.CONVOX_RACK ?? '')) {
    fail('CONVOX_RACK is organization/rack')
  }
  if (config.CONVOX_APP !== environment) {
    fail(`CONVOX_APP must be the environment name '${environment}', got '${config.CONVOX_APP ?? ''}'`)
  }
  if (!ENV_TYPES.includes(config.ENV_TYPE)) {
    fail(`ENV_TYPE must be one of ${ENV_TYPES.join(', ')}, got '${config.ENV_TYPE ?? ''}'`)
  }
  if (!config.CONVOX_MANIFEST) {
    fail('CONVOX_MANIFEST is required')
  }
}

/**
 * Prepares the app on the rack and returns the names of the variables it set to a value. `github` answers
 * { branch(), file(path) } (does it exist on the branch); `run(line)` and `runWithInput(line, input)` run a shell
 * line; `log` prints a workflow command.
 */
export const prepareApp = async ({ env, github, run, runWithInput, log }) => {
  const { PRODUCT: product, ENVIRONMENT: environment, GIT_BRANCH: branch = '' } = env
  const config = parseEnvFile(Buffer.from(env.ENV_FILE_CONTENT ?? '', 'base64').toString('utf8'))
  checkInputs({ env, config })

  const envFile = `apps/${product}/deploy/${environment}.env`
  if (!(await github.branch())) {
    fail(`The branch ${branch} does not exist in ${REPOSITORY}`)
  }
  if (await github.file(envFile)) {
    fail(`${envFile} already exists on ${branch}`)
  }
  for (const file of [config.CONVOX_MANIFEST, config.CONVOX_IGNORE_FILE].filter(Boolean)) {
    if (!(await github.file(file))) {
      fail(`${file} does not exist on ${branch}`)
    }
  }

  const envelope = env.ENVELOPE ?? ''
  if (envelope === '') {
    fail('There is no envelope: the VARIABLES input is empty')
  }
  if ((env.INSTALL_SECRETS_PRIVATE_KEY ?? '') === '') {
    fail('INSTALL_SECRETS_PRIVATE_KEY is not set: it is a secret of this repository')
  }
  const text = decryptEnvelope(envelope, env.INSTALL_SECRETS_PRIVATE_KEY)
  for (const command of maskCommands(envelope, text)) {
    log(command)
  }
  const variables = parseVariables(text)

  const rack = config.CONVOX_RACK
  await run(CONVOX_LOGIN)
  await run(createAppLine({ rack, app: environment, product }))
  if (Object.keys(variables).length > 0) {
    await runWithInput(words('convox', 'env', 'set', '--app', environment, '--rack', rack), text)
  }
  return Object.keys(variables).filter((name) => variables[name] !== '')
}

/** Runs a line with bash, printing it (the lines hold names, never values) and failing when it does. */
export const shell = ({ env = process.env, out = process.stdout, err = process.stderr } = {}) => {
  const run = (line, input) => {
    out.write(`+ ${line}\n`)
    const result = spawnSync('bash', ['-c', line], { env, input, encoding: 'utf8' })
    out.write(result.stdout ?? '')
    err.write(result.stderr ?? '')
    if (result.status !== 0) {
      fail('A command of the install failed (see above)')
    }
  }
  return { run: (line) => run(line), runWithInput: run }
}

const githubOf = (env) => {
  const { GH_OWNER: owner = '', GH_PASSWORD: password = '', GIT_BRANCH: branch = '' } = env
  const authorization = `Basic ${Buffer.from(`${owner}:${password}`).toString('base64')}`
  const present = async (path, what) => {
    const response = await fetch(`https://api.github.com/repos/${REPOSITORY}/${path}`, {
      headers: { Authorization: authorization, Accept: 'application/vnd.github+json' },
    })
    if (response.status === 404) {
      return false
    }
    return response.ok || fail(`GitHub answered ${response.status} about ${what}`)
  }
  const encode = (value) => value.split('/').map(encodeURIComponent).join('/')
  return {
    branch: () => present(`git/ref/heads/${encode(branch)}`, `the branch ${branch}`),
    file: (path) => present(`contents/${encode(path)}?ref=${encodeURIComponent(branch)}`, path),
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const names = await prepareApp({ env: process.env, github: githubOf(process.env), ...shell(), log: console.log })
    // Always "set:", so that an output GitHub drops (it drops one that holds a masked value) is not taken for "none"
    appendFileSync(process.env.GITHUB_OUTPUT, `variables=set:${names.join(',')}\n`)
  } catch (error) {
    console.error(`::error::${error.message}`)
    process.exit(1)
  }
}
