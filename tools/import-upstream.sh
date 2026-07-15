#!/bin/sh
set -ex
have_version=$(cut -d= -f2 src/chrome/VERSION | tr '\n' . | cut -d. -f1-4)
want_version=$(cat CHROMIUM_VERSION)
if [ "$have_version" = "$want_version" ]; then
  exit 0
fi
name="chromium-$want_version"
tarball="$name.tar.xz"
url="https://commondatastorage.googleapis.com/chromium-browser-official/$tarball"
tar=tar
if command -v gtar >/dev/null 2>&1; then
  tar=gtar
fi
root=$(git rev-list --max-parents=0 HEAD)
branch=$(git branch --show-current)
git config core.autocrlf false
git config core.safecrlf false
git -c advice.detachedHead=false checkout $root
rm -rf src
git checkout "$branch" -- tools
# The explicit backup suffix works with both GNU sed and macOS BSD sed.
sed -i.bak "s/^\^/$name\//" tools/include.txt
rm tools/include.txt.bak
if [ -f "/tmp/$tarball" ]; then
  cat "/tmp/$tarball" | "$tar" xJf - --wildcards --wildcards-match-slash -T tools/include.txt -X tools/exclude.txt
else
  curl "$url" -o- | "$tar" xJf - --wildcards --wildcards-match-slash -T tools/include.txt -X tools/exclude.txt
fi
mv "$name" src
git rm --quiet --force -r tools
git add src
git commit --quiet --amend -m "Import $name" --date=now
git rebase --onto HEAD "$root" "$branch"
