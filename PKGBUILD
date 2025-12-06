# Maintainer: Alessio Deiana <adeiana@gmail.com>
pkgname=authd
pkgver=0.1.0
pkgrel=1
pkgdesc="Privilege escalation daemon for Wayland (polkit replacement)"
arch=('x86_64')
url="https://github.com/adeiana/authd"
license=('MIT')
depends=('pam' 'systemd')
makedepends=('cargo' 'clang')
backup=('etc/pam.d/authd')
source=()

build() {
    cd "$startdir"
    cargo build --release --locked
}

package() {
    cd "$startdir"

    # Binaries
    install -Dm755 target/release/authd "$pkgdir/usr/bin/authd"
    install -Dm755 target/release/authctl "$pkgdir/usr/bin/authctl"
    install -Dm755 target/release/pkexec "$pkgdir/usr/bin/authd-pkexec"

    # Systemd service
    install -Dm644 authd.service "$pkgdir/usr/lib/systemd/system/authd.service"

    # PAM config
    install -Dm644 etc/pam.d/authd "$pkgdir/etc/pam.d/authd"

    # Example policy
    install -Dm644 etc/authd/policies.d/gparted.toml "$pkgdir/usr/share/authd/examples/gparted.toml"

    # Create policy directory
    install -dm755 "$pkgdir/etc/authd/policies.d"
}
