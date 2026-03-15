# How to upgarde Chromium version

## Chromium version tracker https://chromiumdash.appspot.com/schedule

## Upgrade version and import minimized upstream Chromium code

```
vi CHROMIUM_VERSION
git add CHROMIUM_VERSION
git commit -m Update
./tools/import-upstream.sh
```

## Format code (In Chromium source tree root directory)

```
clang-format --style=file -i net/tools/naive/*
./third_party/depot_tools/cpplint.py --root=src net/tools/naive/*
```

## Delete all assets in a release

```
[...document.querySelectorAll('.js-release-remove-file')].forEach(e => e.click())
```
