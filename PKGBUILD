# Maintainer: William C. Canin <wcanin.contact@gmail.com>

pkgname=firewall
pkgver=0.1.0
pkgrel=1
pkgdesc='Sample Firewall using Iptables.'
arch=('any')
url='https://github.com/williamcanin/firewall.git'
license=('MIT')
depends=('iptables' 'systemd' 'kmod' 'squid')
source=('firewall.sh' 'firewall.service' 'firewall.conf')
sha512sums=('SKIP' 'SKIP' 'SKIP')

package() {

  ### Using copy
  # mkdir -p "${pkgdir}"/usr/bin
  # mkdir -p "${pkgdir}"/usr/lib/systemd/system
  # mkdir -p "${pkgdir}"/etc
  # cp ${srcdir}/firewall.sh "${pkgdir}"/usr/bin/firewall
  # chown root:root "${pkgdir}"/usr/bin/firewall
  # chmod 700 "${pkgdir}"/usr/bin/firewall
  # chmod +x "${pkgdir}"/usr/bin/firewall
  # cp ${srcdir}/firewall.service "${pkgdir}"/usr/lib/systemd/system
  # chown root:root "${pkgdir}"/usr/lib/systemd/system/firewall.service
  # chmod 700 "${pkgdir}"/usr/lib/systemd/system/firewall.service
  # cp ${srcdir}/firewall.conf "${pkgdir}"/etc
  # chown root:root "${pkgdir}"/etc/firewall.conf
  # chmod 700 "${pkgdir}"/etc/firewall.conf

  # Config
  install -Dm 644 "${srcdir}"/firewall.conf "${pkgdir}"/etc/firewall.conf
  
  # Script
  install -Dm 700 "${srcdir}"/firewall.sh "${pkgdir}"/usr/bin/firewall

  # Service
  install -Dm 644 "${srcdir}"/firewall.service -t "${pkgdir}"/usr/lib/systemd/system
}
