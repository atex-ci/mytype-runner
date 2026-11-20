#!/usr/bin/env node

// The first step of setup-new-instance.yml: opens the envelope of the MyType environment file in memory, masks it, and
// leaves what the old flow received (the base64 of the file, which boot.sh of the branch decodes) in a file of the
// job's temp folder, for the BUILD step to read. It is code of this repository, run before any code of the branch
// is: the installer never sends the file in clear, since a workflow_dispatch input stays readable in the run's event.
//
// The whole file is the secret, and not only the fields that look like one: the runner needs nothing of it before it
// is opened (the name of the environment is the one input that stays in clear), and the file holds the passwords and
// keys boot.sh stores in AWS Secrets Manager next to the settings the install deploys with.
//
// What is masked is the envelope, the base64, and the value of every line whose key looks like a secret, as the BUILD
// step has always done: masking every value would turn a `true` or a `1` into asterisks all over the log.
import { writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { decryptEnvelope, maskCommand } from './decrypt-secrets.mjs'

export const ENV_FILE_NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/
export const SECRET_KEY = /(PASSWORD|SECRET|TOKEN|KEY|DSN|CLIENT_ID)/
const BASE64 = /^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

const fail = (message) => {
  throw new Error(message)
}

/** The values of the lines of an env file whose key looks like a secret, without the quotes around them. */
export const secretValues = (text) =>
  text
    .split('\n')
    .map((line) => line.replace(/\r$/, ''))
    .filter((line) => line.includes('='))
    .map((line) => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)])
    .filter(([key, value]) => SECRET_KEY.test(key) && value !== '')
    .map(([, value]) => value.replace(/^"/, '').replace(/"$/, ''))
    .filter((value) => value !== '')

/**
 * What the BUILD step hands to boot.sh as ENV_FILE_CONTENT: the base64 of the file the installer built, as the old
 * flow received it. `env` has ENVELOPE (the input), INSTALL_SECRETS_PRIVATE_KEY and ENV_FILE_NAME; every mask is
 * logged before the content is returned.
 */
export const openEnvFile = ({ env, log }) => {
  const { ENVELOPE: envelope = '', INSTALL_SECRETS_PRIVATE_KEY: key = '', ENV_FILE_NAME: name = '' } = env
  if (!ENV_FILE_NAME.test(name)) {
    fail('ENV_FILE_NAME is lowercase letters, digits and hyphens, starting and ending with a letter or a digit')
  }
  if (envelope === '') {
    fail('There is no envelope: the ENV_FILE_CONTENT input is empty')
  }
  if (key === '') {
    fail('INSTALL_SECRETS_PRIVATE_KEY is not set: it is a secret of this repository')
  }
  const content = decryptEnvelope(envelope, key, `mytype/${name}`)
  if (!BASE64.test(content)) {
    fail('The environment file in the envelope is not base64')
  }
  const text = Buffer.from(content, 'base64').toString('utf8')
  for (const value of [envelope, content, ...secretValues(text)]) {
    log(maskCommand(value))
  }
  return content
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { OPENED_FILE: file = '' } = process.env
    if (file === '') {
      fail('OPENED_FILE is not set')
    }
    const content = openEnvFile({ env: process.env, log: (line) => console.log(line) })
    // Only this user reads it; the BUILD step reads it, and boot.sh writes the env file from it as before
    writeFileSync(file, content, { mode: 0o600 })
  } catch (error) {
    console.error(error.message)
    process.exit(1)
  }
}
