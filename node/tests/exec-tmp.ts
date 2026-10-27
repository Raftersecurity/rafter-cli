import fs from "fs";
import path from "path";

/**
 * A fresh directory for tests that write a stub binary and execute it.
 *
 * The system temp dir is often mounted noexec, where running the stub fails
 * with EACCES (sable-m8vv). The tests directory is on an executable
 * filesystem wherever this suite can run, so stubs go under it;
 * RAFTER_TEST_EXEC_DIR overrides the base. The caller removes the directory.
 */
export function execTmpDir(prefix: string): string {
  const base = process.env.RAFTER_TEST_EXEC_DIR || path.join(__dirname, ".exec-tmp");
  fs.mkdirSync(base, { recursive: true });
  return fs.mkdtempSync(path.join(base, prefix));
}
