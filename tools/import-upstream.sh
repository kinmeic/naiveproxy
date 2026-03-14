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
root=$(git rev-list --max-parents=0 HEAD)
# Save branch name before going to detached HEAD
branch=$(git rev-parse --abbrev-ref HEAD)
git config core.autocrlf false
git config core.safecrlf false

# Save tools to temp before going to root commit
mkdir -p /tmp/naive-tools-backup
cp -r tools/* /tmp/naive-tools-backup/

git -c advice.detachedHead=false checkout $root
rm -rf src
# Restore tools from temp backup instead of from branch
cp -r /tmp/naive-tools-backup/* tools/
sed -i '' "s/^\\^/$name\//" tools/include.txt
if [ -f "/tmp/$tarball" ]; then
  cat "/tmp/$tarball" | gtar xJf - --wildcards --wildcards-match-slash -T tools/include.txt -X tools/exclude.txt
else
  curl -L "$url" -o "/tmp/$tarball" && cat "/tmp/$tarball" | gtar xJf - --wildcards --wildcards-match-slash -T tools/include.txt -X tools/exclude.txt
fi
mv "$name" src
git rm --quiet --force -r tools
git add src
git commit --quiet --amend -m "Import $name" --date=now
git rebase --onto HEAD "$root" "$branch"
