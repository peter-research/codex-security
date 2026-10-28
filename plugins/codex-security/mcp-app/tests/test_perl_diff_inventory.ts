import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";

const { generateInventory } = await importSource(
  path.join(import.meta.dirname, "../src/helpers/generate-inventory.ts"),
  {
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
          import.meta.url,
        ).href,
      ),
    },
    plugins: [
      {
        name: "test-native-environment",
        setup(build) {
          build.onResolve({ filter: /^\.\.\/native$/ }, () => ({
            path: "native-environment-stub",
            namespace: "test-native",
          }));
          build.onLoad({ filter: /.*/, namespace: "test-native" }, () => ({
            contents: `
                export const unixBinding = () => ({
                  unixEnvironment: name => {
                    const value = process.env[name.toString()];
                    return value === undefined ? null : Buffer.from(value);
                  },
                  userHome: () => ({ errno: 0, value: null }),
                });
                export const windowsBinding = () => { throw new Error("unused"); };
              `,
            loader: "js",
          }));
        },
      },
    ],
  },
);

test(
  "diff inventory includes Perl source extensions and mixed-encoding text",
  { skip: process.platform === "win32" },
  async () => {
    const root = fs.mkdtempSync(path.join(tmpdir(), "perl-diff-inventory-"));
    const repo = path.join(root, "repository");
    fs.mkdirSync(repo);
    const git = (...args: string[]) =>
      execFileSync(
        "git",
        [
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.invalid",
          ...args,
        ],
        { cwd: repo, encoding: "utf8" },
      ).trim();

    try {
      git("init", "-q");
      git("commit", "--allow-empty", "-qm", "base");
      const base = git("rev-parse", "HEAD");
      const sources: [string, Buffer | string][] = [
        ["cgi/handler.cgi", "#!/usr/bin/perl\nprint 'cgi';\n"],
        ["lib/App.pm", "package App;\n1;\n"],
        [
          "script.pl",
          Buffer.from([
            0x70, 0x72, 0x69, 0x6e, 0x74, 0x20, 0xa4, 0xa2, 0x3b, 0x0a,
          ]),
        ],
        ["t/basic.t", "use Test::More;\nok(1, 'test');\n"],
      ];
      for (const [name, contents] of sources) {
        const file = path.join(repo, name);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, contents);
      }
      git("add", ".");
      git("commit", "-qm", "add Perl sources");
      const head = git("rev-parse", "HEAD");
      const output = path.join(root, "in-scope-files.txt");

      assert.equal(
        await generateInventory(
          "generate-in-scope-files",
          { repo, out: output, scope: ".", base, head },
          process.env.HOME ?? root,
        ),
        sources.length,
      );
      assert.deepEqual(
        fs.readFileSync(output, "utf8").trimEnd().split("\n"),
        sources
          .map(([name]) => name)
          .sort((left, right) =>
            Buffer.compare(Buffer.from(left), Buffer.from(right)),
          ),
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);
