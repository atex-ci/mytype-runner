#!/usr/bin/env node

// Makes the RSA pair that protects the secrets of an install and prints the public half:
//
//   node scripts/generate-install-keys.mjs [--replace]
//
// The private key goes to the repository secret INSTALL_SECRETS_PRIVATE_KEY through the standard input of
// `gh secret set`: never on a command line, never on disk, never printed. The public key is the base64 of its SPKI
// DER, the value of INSTALL_SECRETS_PUBLIC_KEY in apps/installer/src/store/constants.ts (atex-products/mytype).
// Needs `gh` logged in with the right to set secrets of atex-ci/mytype-runner. A secret that exists is not replaced
// unless --replace: a new key makes every envelope made with the old public key unreadable.
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { pathToFileURL } from 'node:url'

export const REPOSITORY = 'atex-ci/mytype-runner'
export const SECRET_NAME = 'INSTALL_SECRETS_PRIVATE_KEY'

const gh = (args, input) => spawnSync('gh', args, { input, encoding: 'utf8' })

/** Makes the pair, stores the private key with `run` (gh) and returns the public key. */
export const generateInstallKeys = ({ run = gh, replace = false } = {}) => {
  const listed = run(['secret', 'list', '-R', REPOSITORY, '--json', 'name', '-q', '.[].name'])
  if (listed.status !== 0) {
    throw new Error(`gh could not list the secrets of ${REPOSITORY}: ${listed.stderr?.trim()}`)
  }
  if (listed.stdout.split('\n').includes(SECRET_NAME) && !replace) {
    throw new Error(
      `${SECRET_NAME} already exists in ${REPOSITORY}. A new key makes every envelope made with the old public key unreadable: run again with --replace to do it.`
    )
  }

  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
  const stored = run(['secret', 'set', SECRET_NAME, '-R', REPOSITORY], privateKey.export({ type: 'pkcs8', format: 'pem' }))
  if (stored.status !== 0) {
    throw new Error(`gh could not set ${SECRET_NAME} in ${REPOSITORY}: ${stored.stderr?.trim()}`)
  }
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const publicKey = generateInstallKeys({ replace: process.argv.includes('--replace') })
    console.error(`${SECRET_NAME} is set in ${REPOSITORY}. The public key, for INSTALL_SECRETS_PUBLIC_KEY:`)
    console.log(publicKey)
  } catch (error) {
    console.error(error.message)
    process.exit(1)
  }
}
