class Guardmycopy < Formula
  desc "macOS clipboard firewall for reducing accidental secret pastes"
  homepage "https://github.com/rhushab/guardmycopy"
  url "https://github.com/rhushab/guardmycopy/archive/refs/tags/v1.0.0-rc2.tar.gz"
  version "1.0.0-rc2"
  sha256 "2b4717f2cd2e7928f82c4728d2260bcfabb98d421638ddc98062c3013f2005e7"
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
