// Curated list of very popular npm package names. Two jobs:
//   1. Typosquat/hallucination reference set — names one edit away from these
//      are suspicious (attackers register them; AIs hallucinate near-misses).
//   2. Known-established shortcut — packages on this list skip the "brand-new
//      package" registry deep-dive (their packuments are huge and they are,
//      by definition, not obscure).
// This is a heuristic seed, not a completeness claim. The ML block will learn
// a richer notion of "plausible name" later; rules ship first.

export const POPULAR_PACKAGES: ReadonlySet<string> = new Set([
  // Frameworks & rendering
  "react", "react-dom", "next", "vue", "nuxt", "svelte", "angular", "preact",
  "solid-js", "astro", "remix", "gatsby", "expo", "react-native", "electron",
  "ember-source", "backbone", "alpinejs", "lit", "htmx.org",
  // Servers & networking
  "express", "koa", "fastify", "hapi", "restify", "nest", "@nestjs/core",
  "socket.io", "socket.io-client", "ws", "cors", "body-parser", "cookie-parser",
  "compression", "helmet", "http-proxy", "http-proxy-middleware", "serve",
  "serve-static", "express-session", "multer", "formidable", "busboy",
  // HTTP clients
  "axios", "node-fetch", "got", "superagent", "request", "undici", "ky",
  "cross-fetch", "isomorphic-fetch", "whatwg-fetch",
  // Utilities
  "lodash", "lodash-es", "underscore", "ramda", "immer", "immutable",
  "uuid", "nanoid", "shortid", "classnames", "clsx", "deepmerge", "object-assign",
  "qs", "query-string", "url-parse", "path-to-regexp", "ms", "bytes",
  "semver", "validator", "joi", "yup", "zod", "ajv", "superstruct",
  "change-case", "camelcase", "kebab-case", "slugify", "pluralize",
  "escape-html", "he", "entities", "sanitize-html", "dompurify", "xss",
  // CLI & terminal
  "chalk", "picocolors", "kleur", "colors", "ansi-colors", "commander",
  "yargs", "minimist", "meow", "inquirer", "prompts", "enquirer", "ora",
  "cli-progress", "progress", "boxen", "figlet", "cli-table3", "listr2",
  // Logging & debugging
  "debug", "winston", "pino", "bunyan", "morgan", "loglevel", "signale",
  // Env & config
  "dotenv", "dotenv-expand", "cross-env", "config", "rc", "cosmiconfig",
  "env-cmd", "envalid",
  // FS & paths
  "fs-extra", "graceful-fs", "rimraf", "mkdirp", "glob", "fast-glob",
  "globby", "minimatch", "micromatch", "chokidar", "del", "tmp", "temp",
  "find-up", "pkg-dir", "read-pkg", "write-file-atomic", "cpx", "ncp",
  // Process & tasks
  "nodemon", "pm2", "concurrently", "npm-run-all", "execa", "shelljs",
  "cross-spawn", "which", "node-cron", "cron", "bree", "p-limit", "p-queue",
  "p-map", "p-retry", "async", "bluebird", "rxjs",
  // TypeScript & build
  "typescript", "ts-node", "tsx", "tsup", "ts-jest", "tslib", "type-fest",
  "esbuild", "webpack", "webpack-cli", "webpack-dev-server", "rollup",
  "vite", "parcel", "turbo", "nx", "lerna", "swc", "@swc/core", "terser",
  "uglify-js", "babel-loader", "@babel/core", "@babel/preset-env",
  "@babel/runtime", "core-js", "regenerator-runtime", "browserify",
  // Lint & format
  "eslint", "prettier", "stylelint", "eslint-config-prettier",
  "eslint-plugin-import", "eslint-plugin-react", "eslint-plugin-react-hooks",
  "eslint-plugin-unused-imports", "@typescript-eslint/parser",
  "@typescript-eslint/eslint-plugin", "husky", "lint-staged", "standard",
  // Testing
  "jest", "mocha", "chai", "sinon", "vitest", "cypress", "playwright",
  "@playwright/test", "puppeteer", "jsdom", "supertest", "nock", "msw",
  "testing-library", "@testing-library/react", "@testing-library/jest-dom",
  "ava", "tap", "tape", "karma", "istanbul", "nyc", "c8", "faker",
  "@faker-js/faker",
  // Dates & numbers
  "moment", "dayjs", "date-fns", "luxon", "ms", "numeral", "mathjs",
  "decimal.js", "big.js", "bignumber.js",
  // State & data (frontend)
  "redux", "react-redux", "@reduxjs/toolkit", "zustand", "mobx", "recoil",
  "jotai", "xstate", "swr", "react-query", "@tanstack/react-query",
  "react-router", "react-router-dom", "react-hook-form", "formik",
  "react-select", "react-table", "framer-motion", "react-spring",
  "styled-components", "@emotion/react", "@emotion/styled", "sass", "less",
  "tailwindcss", "postcss", "autoprefixer", "bootstrap", "jquery",
  // Visualization
  "d3", "three", "chart.js", "recharts", "echarts", "plotly.js", "leaflet",
  "mapbox-gl", "konva", "fabric", "pixi.js", "cytoscape",
  // Databases & ORMs
  "mongodb", "mongoose", "pg", "mysql", "mysql2", "sqlite3", "better-sqlite3",
  "redis", "ioredis", "knex", "sequelize", "typeorm", "prisma",
  "@prisma/client", "drizzle-orm", "level", "nedb", "lowdb",
  // Queues & messaging
  "amqplib", "kafkajs", "bull", "bullmq", "bee-queue", "mqtt", "nats",
  // Auth & crypto
  "jsonwebtoken", "jose", "passport", "passport-local", "passport-jwt",
  "bcrypt", "bcryptjs", "argon2", "crypto-js", "tweetnacl", "node-forge",
  "oauth", "openid-client", "next-auth", "cookie", "cookie-signature",
  // Parsing & formats
  "cheerio", "jsdom", "xml2js", "fast-xml-parser", "papaparse", "csv-parse",
  "csv-parser", "js-yaml", "yaml", "toml", "ini", "marked", "markdown-it",
  "remark", "rehype", "gray-matter", "front-matter", "turndown",
  "json5", "jsonc-parser", "strip-json-comments", "form-data", "mime",
  "mime-types", "file-type", "iconv-lite", "buffer", "stream-browserify",
  // Images & files
  "sharp", "jimp", "canvas", "pdfkit", "pdf-lib", "pdfjs-dist", "exceljs",
  "xlsx", "archiver", "adm-zip", "jszip", "unzipper", "tar", "node-tar",
  // Email & comms
  "nodemailer", "mailgun-js", "@sendgrid/mail", "twilio",
  // Cloud SDKs & APIs
  "aws-sdk", "@aws-sdk/client-s3", "firebase", "firebase-admin",
  "@google-cloud/storage", "stripe", "openai", "@anthropic-ai/sdk",
  "@octokit/rest", "discord.js", "telegraf", "node-telegram-bot-api",
  "@supabase/supabase-js", "@vercel/node", "wrangler",
  // GraphQL
  "graphql", "apollo-server", "@apollo/client", "@apollo/server",
  "graphql-tag", "urql", "relay-runtime", "type-graphql",
  // Small-but-critical (frequent squat targets)
  "minimist", "left-pad", "event-stream", "coa", "ua-parser-js",
  "is-odd", "is-even", "is-number", "kind-of", "isarray", "inherits",
  "safe-buffer", "readable-stream", "string_decoder", "process", "punycode",
  "setimmediate", "es6-promise", "promise", "eventemitter3", "events",
  "source-map", "source-map-support", "resolve", "browserslist",
  "caniuse-lite", "node-gyp", "node-pre-gyp", "prebuild-install", "nan",
  "node-addon-api", "bindings", "detect-libc", "opencollective-postinstall",
]);

/** True when `name` (normalized) is on the curated popular list. */
export function isPopularPackage(name: string): boolean {
  return POPULAR_PACKAGES.has(name.toLowerCase());
}
