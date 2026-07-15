#!/bin/sh
# Build an OpenWrt package around the cross-compiled naive executable.
set -eu

: "${PACKAGE_FORMAT:?set PACKAGE_FORMAT to ipk or apk}"
: "${PACKAGE_RELEASE:?set PACKAGE_RELEASE, e.g. 24.10.0}"
: "${PACKAGE_GCC_VER:?set PACKAGE_GCC_VER, e.g. 13.3.0}"
: "${PACKAGE_VERSION:?set PACKAGE_VERSION}"
: "${PACKAGE_OUTPUT_DIR:?set PACKAGE_OUTPUT_DIR}"
: "${OPENWRT_FLAGS:?set OPENWRT_FLAGS}"

case "$PACKAGE_FORMAT" in ipk|apk) ;; *) echo "unsupported PACKAGE_FORMAT: $PACKAGE_FORMAT" >&2; exit 2;; esac

eval "$OPENWRT_FLAGS"
repo_root=$(CDPATH= cd -- "$PWD/.." && pwd)
naive_binary="$PWD/out/Release/naive"
test -f "$naive_binary"
sdk_root="$PWD/out/openwrt-sdk/$PACKAGE_FORMAT/$PACKAGE_RELEASE/$arch"
sdk_dir="$sdk_root/openwrt-sdk-$PACKAGE_RELEASE-$target-$subtarget"

if [ ! -f "$sdk_dir/Makefile" ]; then
  mkdir -p "$sdk_root"
  major=${PACKAGE_RELEASE%%.*}
  if [ "$major" -ge 24 ]; then
    suffix=zst
  else
    suffix=xz
  fi
  sdk_name="openwrt-sdk-$PACKAGE_RELEASE-$target-$subtarget"_gcc-"$PACKAGE_GCC_VER"_musl.Linux-x86_64
  url="https://downloads.openwrt.org/releases/$PACKAGE_RELEASE/targets/$target/$subtarget/$sdk_name.tar.$suffix"
  curl --fail --location --retry 3 "$url" -o "$sdk_root/$sdk_name.tar.$suffix"
  if [ "$suffix" = zst ]; then
    tar --zstd -xf "$sdk_root/$sdk_name.tar.$suffix" -C "$sdk_root"
  else
    tar -xJf "$sdk_root/$sdk_name.tar.$suffix" -C "$sdk_root"
  fi
  mv "$sdk_root/$sdk_name" "$sdk_dir"
fi

rm -rf "$sdk_dir/package/naiveproxy"
mkdir -p "$sdk_dir/package/naiveproxy"
cp "$repo_root/openwrt/naiveproxy/Makefile" "$sdk_dir/package/naiveproxy/"

cd "$sdk_dir"
if [ "$PACKAGE_FORMAT" = apk ]; then
  echo 'CONFIG_USE_APK=y' >> .config
else
  echo '# CONFIG_USE_APK is not set' >> .config
fi
echo 'CONFIG_PACKAGE_naiveproxy=y' >> .config
make defconfig
make package/naiveproxy/compile V=s \
  NAIVE_BINARY="$naive_binary" \
  NAIVE_VERSION="${PACKAGE_VERSION#v}"

mkdir -p "$PACKAGE_OUTPUT_DIR"
package=$(find bin -type f -name "naiveproxy*.${PACKAGE_FORMAT}" -print -quit)
test -n "$package"
cp "$package" "$PACKAGE_OUTPUT_DIR/naiveproxy-${PACKAGE_VERSION#v}-openwrt-${arch}.${PACKAGE_FORMAT}"
