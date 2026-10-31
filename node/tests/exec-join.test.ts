import { describe, it, expect } from "vitest";
import { joinCommandParts } from "../src/commands/agent/exec.js";

// `rafter agent exec -- rm -rf "$DIR"` arrives as several argv words. The
// string the classifier evaluates must be the string the shell will run, so
// words are re-quoted rather than joined with bare spaces (rf-ss67).
describe("joinCommandParts", () => {
  it("returns a single quoted argument verbatim", () => {
    expect(joinCommandParts(['echo "a b"'])).toBe('echo "a b"');
  });

  it("joins plain words with spaces", () => {
    expect(joinCommandParts(["echo", "hello", "world"])).toBe("echo hello world");
  });

  it("re-quotes words that contain whitespace or shell metacharacters", () => {
    expect(joinCommandParts(["echo", "a b"])).toBe("echo 'a b'");
    expect(joinCommandParts(["rm", "-rf", "$WORK_DIR"])).toBe("rm -rf '$WORK_DIR'");
    expect(joinCommandParts(["sh", "-c", "rm -rf /"])).toBe("sh -c 'rm -rf /'");
  });

  it("escapes embedded single quotes and keeps empty words", () => {
    expect(joinCommandParts(["echo", "it's"])).toBe("echo 'it'\\''s'");
    expect(joinCommandParts(["echo", ""])).toBe("echo ''");
  });
});
