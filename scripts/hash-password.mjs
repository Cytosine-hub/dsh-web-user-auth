#!/usr/bin/env node
/**
 * Print a scrypt hash suitable for `local.users[].passwordHash`.
 *
 * Usage:
 *   node scripts/hash-password.mjs 'correct horse battery staple'
 *   node scripts/hash-password.mjs            # prompts on stdin
 */
import { createInterface } from 'node:readline/promises'
import { stdin, stdout } from 'node:process'
import { hashPassword } from '../lib/users.js'

let password = process.argv[2]
if (password === undefined) {
  const prompt = createInterface({ input: stdin, output: stdout })
  password = await prompt.question('Password: ')
  prompt.close()
}
if (password.length < 8) {
  console.error('Use at least 8 characters.')
  process.exit(1)
}
console.log(hashPassword(password))
