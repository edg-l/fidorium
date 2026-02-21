# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

CRATES="
	aead-0.5.2
	aes-0.8.4
	aes-gcm-0.10.3
	aho-corasick-1.1.4
	anstream-0.6.21
	anstyle-1.0.13
	anstyle-parse-0.2.7
	anstyle-query-1.1.5
	anstyle-wincon-3.0.11
	anyhow-1.0.102
	autocfg-1.5.0
	base16ct-0.2.0
	base64ct-1.8.3
	bindgen-0.71.1
	bitfield-0.17.0
	bitflags-2.11.0
	block-buffer-0.10.4
	cexpr-0.6.0
	cfg-if-1.0.4
	ciborium-0.2.2
	ciborium-io-0.2.2
	ciborium-ll-0.2.2
	cipher-0.4.4
	clang-sys-1.8.1
	clap-4.5.60
	clap_builder-4.5.60
	clap_derive-4.5.55
	clap_lex-1.0.0
	colorchoice-1.0.4
	const-oid-0.9.6
	cpufeatures-0.2.17
	crunchy-0.2.4
	crypto-bigint-0.5.5
	crypto-common-0.1.7
	ctr-0.9.2
	der-0.7.10
	der_derive-0.7.3
	digest-0.10.7
	directories-6.0.0
	dirs-sys-0.5.0
	ecdsa-0.16.9
	either-1.15.0
	elliptic-curve-0.13.8
	enumflags2-0.7.12
	enumflags2_derive-0.7.12
	equivalent-1.0.2
	errno-0.3.14
	fastrand-2.3.0
	fd-lock-4.0.4
	ff-0.13.1
	flagset-0.4.7
	foldhash-0.1.5
	generic-array-0.14.7
	getrandom-0.2.17
	getrandom-0.4.1
	ghash-0.5.1
	glob-0.3.3
	group-0.13.0
	half-2.7.1
	hashbrown-0.15.5
	hashbrown-0.16.1
	heck-0.5.0
	home-0.5.12
	hostname-validator-1.1.1
	id-arena-2.3.0
	indexmap-2.13.0
	inout-0.1.4
	is_terminal_polyfill-1.70.2
	itertools-0.13.0
	itoa-1.0.17
	lazy_static-1.5.0
	leb128fmt-0.1.0
	libc-0.2.182
	libredox-0.1.12
	linux-raw-sys-0.11.0
	linux-raw-sys-0.4.15
	log-0.4.29
	malloced-1.3.1
	matchers-0.2.0
	memchr-2.8.0
	minimal-lexical-0.2.1
	mio-1.1.1
	nom-7.1.3
	nu-ansi-term-0.50.3
	num-derive-0.4.2
	num-traits-0.2.19
	once_cell-1.21.3
	once_cell_polyfill-1.70.2
	opaque-debug-0.3.1
	option-ext-0.2.0
	paste-1.0.15
	pem-rfc7468-0.7.0
	percent-encoding-2.3.2
	pin-project-lite-0.2.16
	pinentry-0.5.1
	pkcs8-0.10.2
	pkg-config-0.3.32
	polyval-0.6.2
	ppv-lite86-0.2.21
	prettyplease-0.2.37
	proc-macro2-1.0.106
	quote-1.0.44
	r-efi-5.3.0
	rand-0.8.5
	rand_chacha-0.3.1
	rand_core-0.6.4
	redox_users-0.5.2
	regex-1.12.3
	regex-automata-0.4.14
	regex-syntax-0.8.9
	rustc-hash-2.1.1
	rustix-0.38.44
	rustix-1.1.3
	sec1-0.7.3
	secrecy-0.8.0
	semver-1.0.27
	serde-1.0.228
	serde_core-1.0.228
	serde_derive-1.0.228
	serde_json-1.0.149
	sha2-0.10.9
	sharded-slab-0.1.7
	shlex-1.3.0
	signal-hook-registry-1.4.8
	signature-2.2.0
	smallvec-1.15.1
	spki-0.7.3
	strsim-0.11.1
	subtle-2.6.1
	syn-2.0.117
	target-lexicon-0.13.5
	tempfile-3.25.0
	thiserror-2.0.18
	thiserror-impl-2.0.18
	thread_local-1.1.9
	tls_codec-0.4.2
	tls_codec_derive-0.4.2
	tokio-1.49.0
	tokio-macros-2.6.0
	tracing-0.1.44
	tracing-attributes-0.1.31
	tracing-core-0.1.36
	tracing-log-0.2.0
	tracing-subscriber-0.3.22
	tss-esapi-8.0.0-alpha.1
	tss-esapi-sys-0.6.0-alpha.1
	typenum-1.19.0
	uhid-virt-0.0.8
	uhidrs-sys-1.0.4
	unicode-ident-1.0.24
	unicode-xid-0.2.6
	universal-hash-0.5.1
	utf8parse-0.2.2
	valuable-0.1.1
	version_check-0.9.5
	wasi-0.11.1+wasi-snapshot-preview1
	wasip2-1.0.2+wasi-0.2.9
	wasip3-0.4.0+wasi-0.3.0-rc-2026-01-06
	wasm-encoder-0.244.0
	wasm-metadata-0.244.0
	wasmparser-0.244.0
	which-4.4.2
	windows-link-0.2.1
	windows-sys-0.59.0
	windows-sys-0.61.2
	windows-targets-0.52.6
	windows_aarch64_gnullvm-0.52.6
	windows_aarch64_msvc-0.52.6
	windows_i686_gnu-0.52.6
	windows_i686_gnullvm-0.52.6
	windows_i686_msvc-0.52.6
	windows_x86_64_gnu-0.52.6
	windows_x86_64_gnullvm-0.52.6
	windows_x86_64_msvc-0.52.6
	wit-bindgen-0.51.0
	wit-bindgen-core-0.51.0
	wit-bindgen-rust-0.51.0
	wit-bindgen-rust-macro-0.51.0
	wit-component-0.244.0
	wit-parser-0.244.0
	x509-cert-0.2.5
	zerocopy-0.8.39
	zerocopy-derive-0.8.39
	zeroize-1.8.2
	zeroize_derive-1.4.3
	zmij-1.0.21
"

inherit cargo linux-info optfeature systemd udev

DESCRIPTION="FIDO2/CTAP2 hardware authenticator daemon backed by TPM2"
HOMEPAGE="https://github.com/edg-l/fidorium"
SRC_URI="
	https://github.com/edg-l/fidorium/archive/refs/tags/v${PV}.tar.gz -> ${P}.tar.gz
	${CARGO_CRATE_URIS}
"

LICENSE="MIT Apache-2.0"
# Crate licenses: see 'cargo license' for full list; all are MIT/Apache-2.0/BSD
LICENSE+=" MIT Apache-2.0 BSD ISC Unicode-DFS-2016 Unlicense ZLIB"
SLOT="0"
KEYWORDS="~amd64"
IUSE="systemd"

CONFIG_CHECK="~UHID"
ERROR_UHID="fidorium requires CONFIG_UHID (Virtual HID devices) to be enabled in the kernel."

# tss-esapi-sys uses bindgen at build time, which requires libclang.
BDEPEND="
	llvm-core/clang
	virtual/pkgconfig
"

DEPEND="
	app-crypt/tpm2-tss
"

RDEPEND="
	${DEPEND}
	app-crypt/pinentry
"

DOCS=( ARCHITECTURE.md )

pkg_setup() {
	rust_pkg_setup
	linux-info_pkg_setup
}

src_configure() {
	cargo_src_configure
}

src_compile() {
	cargo_src_compile
}

src_install() {
	cargo_src_install

	# udev rule for /dev/uhid access
	udev_dorules dist/99-fidorium.rules

	# OpenRC user init script + conf.d
	insinto /etc/user/init.d
	insopts -m0755
	newins dist/fidorium.initd fidorium
	insinto /etc/user/conf.d
	insopts -m0644
	newins dist/fidorium.confd fidorium

	# systemd user service (installed system-wide; users enable per-session)
	systemd_douserunit dist/fidorium.service

	einstalldocs
}

pkg_postinst() {
	udev_reload

	elog "To allow your user to access /dev/uhid without root:"
	elog "  sudo usermod -aG input \${USER}"
	elog "  (then log out and back in)"
	elog ""
	elog "To allow your user to access the TPM device:"
	elog "  sudo usermod -aG tss \${USER}"
	elog ""
	optfeature "curses-based pinentry dialog (for headless/TTY use)" \
		"app-crypt/pinentry[ncurses]"
	optfeature "GTK pinentry dialog" \
		"app-crypt/pinentry[gtk]"
	optfeature "Qt pinentry dialog" \
		"app-crypt/pinentry[qt5]"
	elog ""
	elog "OpenRC: rc-update --user add fidorium && rc-service --user fidorium start"
	elog "systemd: systemctl --user enable --now fidorium"
}
