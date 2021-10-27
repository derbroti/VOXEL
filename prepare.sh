#!/bin/bash

start_step=1

if [ $# -ne 0 ]
then
	[ ! -z "${1##*[!0-9]*}" ] && start_step=$1 || start_step=1
else
	echo "To restart the script at any numbered step, provide this number as argument"
	echo ""
	echo "<No start step given, starting at beginning.>"
	echo ""
fi

if [ $start_step -eq 1 ]
then

echo "------------------------------"
echo "(1) creating base folder \"chrome\""
echo "------------------------------"

mkdir chrome
cd chrome

start_step=2
fi

if [ $start_step -eq 2 ]
then
echo "------------------------------"
echo "(2) install depot tools -> build tools: gclient, gn, ninja, etc. needed to build chrome"
echo "------------------------------"

git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git

export PATH="$PATH:$(pwd)/depot_tools"

start_step=3
fi

if [ $start_step -eq 3 ]
then
echo "------------------------------"
echo "(3) running gclient to setup chromium source @ commit: e48ee88"
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

start_step=4
fi

if [ $start_step -eq 4 ]
then

echo "------------------------------"
echo "(4) installing internal dependencies"
echo "------------------------------"

gclient runhooks
cd ../..

start_step=5
fi

if [ $start_step -eq 5 ]
then

echo "------------------------------"
echo "(5) appling SlipStream modifications"
echo "------------------------------"

./update-mod-links.sh
cd chrome/src

start_step=6
fi

if [ $start_step -eq 6 ]
then

echo "------------------------------"
echo "(6) creating release environment"
echo "------------------------------"

gn gen out/Release

start_step=7
fi

if [ $start_step -eq 7 ]
then

echo "------------------------------"
echo "(7) first build (needs to fail)"
echo "------------------------------"

ninja -C out/Release quic_server quic_client
cd ../..

start_step=8
fi

if [ $start_step -eq 8 ]
then

echo "------------------------------"
echo "(8) final build"
echo "------------------------------"

./make.sh

fi
