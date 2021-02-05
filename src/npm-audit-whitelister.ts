#!/usr/bin/env node

import { exec } from 'child_process';
import * as fs from 'fs';

const INVALID_FILE = 'Invalid Whitelist File';

async function main(_args: string[]): Promise<void> {
  // parge command args
  const [whitelistFilename] = _args;

  const ignoreLevel: AuditLevel | undefined = process.env
    .NPM_AUDIT_IGNORE_LEVEL as any;
  if (ignoreLevel !== undefined && !AuditLevels.includes(ignoreLevel)) {
    throw new Error('Invalid NPM_AUDIT_IGNORE_LEVEL');
  }

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
    //   "jest:1500",
    //   ".*>yarn:1720"
    // ]
    const whitelistData: PackageIdPair[] = fileJson.map(
      (item: string): PackageIdPair => {
        const splitData = item.split(':');
        if (
          splitData.length !== 2 ||
          !splitData[1] ||
          !splitData[1].match(/^\d+$/) ||
          !splitData[0] ||
          splitData[0].match(/:/)
        )
          throw new Error(INVALID_FILE);
        try {
          new RegExp(splitData[0]);
        } catch (e) {
          throw new Error(INVALID_FILE);
        }
        return {
          id: parseInt(splitData[1], 10),
          package: splitData[0],
        };
      },
    );
    whiteList.push(...whitelistData);
  }

  // Run npm audit and parse the results
  const data = await npmAudit(ignoreLevel);

  // Find errors
  const packagePairs: string[] = [];
  data.actions.forEach(action => {
    action.resolves.forEach(resolve => {
      if (resolve.dev && process.env.NPM_AUDIT_IGNORE_DEV) return;

      const searchData = {
        id: resolve.id,
        package: resolve.path,
      };
      if (
        !whiteList.some(entry => {
          let regex = entry.package;
          if (regex.startsWith('^')) regex = regex.slice(1);
          if (regex.endsWith('$')) regex = regex.slice(0, regex.length - 1);
          return (
            entry.id === searchData.id &&
            searchData.package.match(new RegExp(`^${regex}$`))
          );
        })
      ) {
        // Replace any hex-only intermediate packages with regex for them
        // Since these hex packages change with every npm audit invocation
        const pkg = searchData.package.replace(
          /(?<=(^|>))[0-9a-fA-F]+(?=>)/g,
          '[0-9a-fA-F]+',
        );
        packagePairs.push(`${pkg}:${searchData.id}`);
      }
    });
  });
  if (packagePairs.length > 0) {
    const uniqueErrors = packagePairs.filter((item, index, arr) => {
      return arr.indexOf(item) === index;
    });
    throw new Error(
      'Found non-whitelisted audit vulnerability(s):\n\n[\n  "' +
        uniqueErrors.join('",\n  "') +
        '"\n]\n',
    );
  }
}

async function npmAudit(ignoreLevel?: AuditLevel): Promise<INpmAuditResult> {
  const cmdString =
    ignoreLevel === undefined
      ? 'npm audit --json'
      : `npm audit --json --audit-level=${ignoreLevel}`;
  const result = await cmd(cmdString, { cwd: process.env.PWD }).then(
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

interface CmdOutput {
  code: number;
  stdout: string;
  stderr: string;
}

interface PackageIdPair {
  id: number;
  package: string;
}

enum ActionType {
  INSTALL = 'install',
  UPDATE = 'update',
  REVIEW = 'review',
}

interface IResolvedByAction {
  id: number;
  path: string;
  dev: boolean;
  optional: boolean;
  bundled: boolean;
}

interface IAction {
  action: ActionType;
  module: string;
  target: string;
  isMajor: boolean;
  depth?: number;
  resolves: IResolvedByAction[];
}

type AuditLevel = 'low' | 'moderate' | 'high' | 'critical';
const AuditLevels = ['low', 'moderate', 'high', 'critical'];

// incomplete
interface INpmAuditResult {
  actions: IAction[];
}

main(process.argv.slice(2)).catch(err => {
  // tslint:disable-next-line:no-console
  console.error(err);
  process.exit(1);
});
