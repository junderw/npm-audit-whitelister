#!/usr/bin/env node

import { exec } from 'child_process';
import * as fs from 'fs';

import {
  AuditLevel,
  AuditLevels,
  CmdOutput,
  PackageIdPair,
  Root,
  Via,
} from './types';

const INVALID_FILE = 'Invalid Whitelist File';

async function main(_args: string[]): Promise<void> {
  // parge command args
  const [whitelistFilename] = _args;

  const ignoreLevel: AuditLevel | undefined = process.env
    .NPM_AUDIT_IGNORE_LEVEL as any;
  if (ignoreLevel !== undefined && !AuditLevels.includes(ignoreLevel)) {
    throw new Error('Invalid NPM_AUDIT_IGNORE_LEVEL');
  }
  const maxBuffer = process.env.CMD_MAX_BUFFER
    ? parseInt(process.env.CMD_MAX_BUFFER, 10)
    : undefined;

  // parse whitelist
  const whiteList: PackageIdPair[] = [];
  if (whitelistFilename !== undefined) {
    const stats = fs.statSync(whitelistFilename);
    if (!stats.isFile()) {
      throw new Error(INVALID_FILE);
    }
    const fileData = fs.readFileSync(whitelistFilename, 'utf8');
    let fileJson: string[];
    try {
      fileJson = JSON.parse(fileData);
    } catch (e) {
      throw new Error(INVALID_FILE);
    }
    // format: Array JSON of packagePathRegExp:advisoryID
    // [
    //   "explain:node,node,node:1500"
    // ]
    const whitelistData: PackageIdPair[] = fileJson.map(
      (item: string): PackageIdPair => {
        const splitData = item.split(':');
        if (
          splitData.length !== 3 ||
          !splitData[2] ||
          !splitData[2].match(/^\d+$/) ||
          !splitData[1]
        )
          throw new Error(INVALID_FILE);
        return {
          id: parseInt(splitData[2], 10),
          nodes: splitData[1].split(','),
        };
      },
    );
    whiteList.push(...whitelistData);
  }

  // Run npm audit and parse the results
  const data = await npmAudit(ignoreLevel, maxBuffer);
  const vias = Object.values(data.vulnerabilities).reduce(
    (acc, vuln) => {
      vuln.via.forEach(via => {
        if (typeof via !== 'string') {
          acc.set(via.source, via);
        }
      });
      return acc;
    },
    new Map() as Map<number, Via>,
  );

  // Find errors
  const ignoreStrings: string[] = [];
  for (const via of vias.values()) {
    const wl = whiteList.find(w => w.id === via.source);
    const top = data.vulnerabilities[via.name];
    if (wl && top.nodes.every(node => wl.nodes.includes(node))) {
      continue;
    }
    // tslint:disable-next-line:no-console
    console.error(
      `Found non-whitelisted vuln: ${via.source} ${via.name} (${
        via.severity
      })\n  ${via.title}`,
    );
    // tslint:disable-next-line:no-console
    console.error(`Node modules path: ${JSON.stringify(top.nodes, null, 2)}\n`);
    ignoreStrings.push(
      `${via.name} (${via.severity}) ${via.title.replace(
        ':',
        '|',
      )}:${top.nodes.join(',')}:${via.source}`,
    );
  }

  if (ignoreStrings.length > 0) {
    const uniqueErrors = ignoreStrings.filter((item, index, arr) => {
      return arr.indexOf(item) === index;
    });
    throw new Error(
      'Found non-whitelisted audit vulnerability(s):\n\n[\n  "' +
        uniqueErrors.join('",\n  "') +
        '"\n]\n',
    );
  }
}

async function npmAudit(
  ignoreLevel?: AuditLevel,
  maxBuffer: number = 100 * 1024 * 1024,
): Promise<Root> {
  let cmdString = 'npm audit --json';
  if (ignoreLevel === undefined) {
    cmdString += ` --audit-level=${ignoreLevel}`;
  }
  if (process.env.NPM_AUDIT_IGNORE_DEV) {
    cmdString += ` --omit=dev`;
  }
  const result = await cmd(cmdString, { cwd: process.env.PWD, maxBuffer }).then(
    v => v,
    e => e as CmdOutput,
  );
  return JSON.parse(result.stdout);
}

async function cmd(command: string, opts = {}): Promise<CmdOutput> {
  return new Promise(
    (resolve, reject): void => {
      exec(
        command,
        opts,
        (err, stdout, stderr): void => {
          if (err) reject(Object.assign(err, { stdout, stderr }));
          else
            resolve({
              code: 0,
              stdout,
              stderr,
            });
        },
      );
    },
  );
}

main(process.argv.slice(2)).catch(err => {
  // tslint:disable-next-line:no-console
  console.error(err);
  process.exit(1);
});
