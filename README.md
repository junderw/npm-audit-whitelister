# npm-audit-whitelister

## About

Install to get `npm-audit-whitelister` command.

## Usage

```
./node_modules/.bin/npm-audit-whitelister .npmaudit.whitelist.json
```

Or in package.json script

```
    "audit": "npm-audit-whitelister .npmaudit.whitelist.json",
```

## Whitelist file format

`PACKAGE-REGEX:VULNCODE`

PACKAGE-REGEX can be a package dependency string or a regex string. It must not have a : in it.

VULNCODE must be a number for the advisoryID.

All three of the below whitelist entries are varying ways of doing the same package.

1. exact
2. any instance where yargs-parser has vuln 1500
3. any dependency of import-sort-cli that has vuln 1500

```
[
  "import-sort-cli>yargs>yargs-parser:1500",
  ".*>yargs-parser:1500",
  "import-sort-cli>.*:1500"
]
```
