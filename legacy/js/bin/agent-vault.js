#!/usr/bin/env node
import { main } from '../src/cli/index.js'
main().catch((e) => { console.error(e.message); process.exit(1) })
