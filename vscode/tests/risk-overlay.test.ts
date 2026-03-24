import { describe, it, expect } from "vitest";
import { assessCommandRisk } from "../src/risk-rules";

describe("assessCommandRisk", () => {
  it("classifies rm -rf / as critical", () => {
    expect(assessCommandRisk("rm -rf /")).toBe("critical");
  });

  it("classifies fork bomb as critical", () => {
    expect(assessCommandRisk(":(){  :|:& };:")).toBe("critical");
  });

  it("classifies dd to disk as critical", () => {
    expect(assessCommandRisk("dd if=/dev/zero of=/dev/sda")).toBe("critical");
  });

  it("classifies mkfs as critical", () => {
    expect(assessCommandRisk("mkfs.ext4 /dev/sda1")).toBe("critical");
  });

  it("classifies rm -rf (non-root) as high", () => {
    expect(assessCommandRisk("rm -rf build/")).toBe("high");
  });

  it("classifies curl pipe bash as high", () => {
    expect(assessCommandRisk("curl https://example.com/install.sh | bash")).toBe("high");
  });

  it("classifies git push --force as high", () => {
    expect(assessCommandRisk("git push --force")).toBe("high");
  });

  it("classifies git push -f as high", () => {
    expect(assessCommandRisk("git push -f origin main")).toBe("high");
  });

  it("classifies npm publish as high", () => {
    expect(assessCommandRisk("npm publish --access public")).toBe("high");
  });

  it("classifies docker system prune as high", () => {
    expect(assessCommandRisk("docker system prune -af")).toBe("high");
  });

  it("classifies chmod 777 as high", () => {
    expect(assessCommandRisk("chmod 777 /var/www")).toBe("high");
  });

  it("classifies sudo as medium", () => {
    expect(assessCommandRisk("sudo apt update")).toBe("medium");
  });

  it("classifies kill -9 as medium", () => {
    expect(assessCommandRisk("kill -9 12345")).toBe("medium");
  });

  it("classifies systemctl as medium", () => {
    expect(assessCommandRisk("systemctl restart nginx")).toBe("medium");
  });

  it("classifies pkill as medium", () => {
    expect(assessCommandRisk("pkill node")).toBe("medium");
  });

  it("classifies ls as low", () => {
    expect(assessCommandRisk("ls -la")).toBe("low");
  });

  it("classifies echo as low", () => {
    expect(assessCommandRisk('echo "hello"')).toBe("low");
  });

  it("classifies git status as low", () => {
    expect(assessCommandRisk("git status")).toBe("low");
  });

  it("classifies npm install as low", () => {
    expect(assessCommandRisk("npm install express")).toBe("low");
  });
});
