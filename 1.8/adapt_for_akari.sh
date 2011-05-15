#!/bin/bash

# example usage:
#   ./adapt_for_akari.sh index.html.en chapter-1.html.en *.html.en ...
#   find -iname '*.html.en' -exec ./adapt_for_akari.sh '{}' \;

for i in $@; do
	sed -i -e 's/<title>TOMOYO Linux 1.8.x :/<title>AKARI :/g' ${i}
	sed -i -e 's/tomoyotitle.png/akarititle.png/g' ${i}
	sed -i -e 's/akarititle.png" width="320"/akarititle.png" width="174"/g' ${i}
	sed -i -e 's/title="TOMOYO Linux Home Page"/title="AKARI Home Page"/g' ${i}
	sed -i -e 's/title="About TOMOYO Linux"/title="About AKARI"/g' ${i}
	sed -i -e '/tomoyo-changelogs/d' ${i}
	sed -i -e '/tomoyo-download/d' ${i}
done

# The following replacement results in some unwanted changes so is not included:
#   sed -i -e 's/TOMOYO Linux/AKARI/g' ${i}
