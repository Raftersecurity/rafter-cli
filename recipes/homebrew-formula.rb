# Homebrew formula for Rafter CLI
#
# To use this formula, create a tap repo (raftersecurity/homebrew-rafter)
# and place this file at Formula/rafter.rb.
#
# Users install with:
#   brew tap raftersecurity/rafter
#   brew install rafter
#
# Or directly:
#   brew install raftersecurity/rafter/rafter

class Rafter < Formula
  desc "Security agent for AI workflows — secret scanning, command interception, audit logging"
  homepage "https://rafter.so"
  url "https://registry.npmjs.org/@rafter-security/cli/-/cli-0.6.5.tgz"
  sha256 :no_check # Replace with actual SHA256 from npm registry
  license "MIT"

  depends_on "node"

  def install
    system "npm", "install", *std_npm_args
    bin.install_symlink Dir["#{libexec}/bin/*"]
  end

  test do
    assert_match "rafter", shell_output("#{bin}/rafter --version")
  end
end
