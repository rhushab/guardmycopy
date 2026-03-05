class Guardmycopy < Formula
  desc "macOS clipboard firewall for reducing accidental secret pastes"
  homepage "https://github.com/rhushab/guardmycopy"
  url "https://github.com/rhushab/guardmycopy/archive/refs/tags/v1.0.0-rc2.tar.gz"
  version "1.0.0-rc2"
  sha256 "REPLACE_WITH_V1_0_0_RC2_TARBALL_SHA256"
  license "MIT"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/guardmycopy"
  end

  test do
    output = shell_output("#{bin}/guardmycopy --help")
    assert_match "guardmycopy <command>", output
  end
end
