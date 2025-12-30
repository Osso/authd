# Maintainer: Alessio Deiana <adeiana@gmail.com>
pkgname=authd
pkgver=0.1.0
pkgrel=1
pkgdesc="Privilege escalation daemon for Wayland (polkit replacement)"
arch=('x86_64')
url="https://github.com/adeiana/authd"
license=('MIT')
depends=('systemd')
makedepends=('cargo' 'musl')
install=authd.install
source=()

build() {
    cd "$startdir"
    cargo build --release --locked --target x86_64-unknown-linux-musl
}

package() {
    cd "$startdir"
    local _target=target/x86_64-unknown-linux-musl/release

    # Binaries
    install -Dm755 "$_target/authd" "$pkgdir/usr/bin/authd"
    install -Dm755 "$_target/authctl" "$pkgdir/usr/bin/authctl"
    install -Dm755 "$_target/pkexec" "$pkgdir/usr/bin/authd-pkexec"

    # authsudo - setuid root for CLI privilege escalation
    install -Dm4755 "$_target/authsudo" "$pkgdir/usr/bin/authsudo"

    # Systemd service
    install -Dm644 authd.service "$pkgdir/usr/lib/systemd/system/authd.service"

    # Example policy
    install -Dm644 etc/authd/policies.d/gparted.toml "$pkgdir/usr/share/authd/examples/gparted.toml"

    # Create policy directory
    install -dm755 "$pkgdir/etc/authd/policies.d"

    # Pacman hook to replace pkexec after polkit updates
    install -Dm644 authd-pkexec.hook "$pkgdir/usr/share/libalpm/hooks/authd-pkexec.hook"
}
