# Information about this repository

This repository has been formed from the original mist-c99 repository at ControlThings Oy Ab using the following commands:

```sh
git clone --single-branch -b v1.0.0-release foremost.controlthings.fi:/ct/mist/mist-c99 mist-c99-apache2 --depth 1
echo 2cd888b87deba5a66e60661636fce129c2f19b16 >.git/info/grafts
git filter-branch -- --all
git remote remove origin
#Check that there are not other remotes
git prune
git gc --aggressive
```
