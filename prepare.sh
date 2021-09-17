#!/bin/bash

echo "------------------------------"
echo "creating base folder \"chrome\""
echo "------------------------------"

mkdir chrome
cd chrome



echo "------------------------------"
echo "install depot tools -> build tools: gclient, gn, ninja, etc. needed to build chrome"
echo "------------------------------"

git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git

export PATH="$PATH:$(pwd)/depot_tools"

echo "------------------------------"
echo "running gclient to setup chromium source @ commit: e48ee88"
echo "------------------------------"

gclient root
gclient config --spec 'solutions = [
  {
	      "url": "https://chromium.googlesource.com/chromium/src.git",
	          "managed": False,
		      "name": "src",
		          "custom_deps": {},
			      "custom_vars": {},
			        },
				]
				'

gclient sync --nohooks --revision e48ee88

cd src
git submodule foreach 'git config -f $toplevel/.git/config submodule.$name.ignore all'
git config --add remote.origin.fetch '+refs/tags/*:refs/tags/*'
git config diff.ignoreSubmodules all


echo "------------------------------"
echo "installing internal dependencies"
echo "------------------------------"

gclient runhooks


echo "------------------------------"
echo "appling SlipStream modifications"
echo "------------------------------"

cd ../..
./update-mod-links.sh
cd chrome/src

echo "------------------------------"
echo "creating release environment"
echo "------------------------------"

gn gen out/Release

echo "------------------------------"
echo "first build (needs to fail)"
echo "------------------------------"

ninja -C out/Release quic_server quic_client

echo "------------------------------"
echo "final build"
echo "------------------------------"

cd ../..
./make.sh
