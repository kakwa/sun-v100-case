#!/bin/bash

cd `dirname $0`

# Ensure you're in a Git repo
if [ ! -d .git ]; then
    echo "Not in a Git repository."
    exit 1
fi

# Add diff 'zip' driver to .git/config if not already present
if ! git config --local --get diff.zip.textconv > /dev/null; then
    git config --local diff.zip.textconv "unzip -c -a"
    echo "Configured diff.zip.textconv in .git/config"
else
    echo "diff.zip.textconv already configured"
fi

# Add *.FCStd diff=zip to .gitattributes
ATTR_LINE="*.FCStd diff=zip"
if [ ! -f .gitattributes ]; then
    echo "$ATTR_LINE" > .gitattributes
    echo "Created .gitattributes with $ATTR_LINE"
elif ! grep -qF "$ATTR_LINE" .gitattributes; then
    echo "$ATTR_LINE" >> .gitattributes
    echo "Appended $ATTR_LINE to .gitattributes"
else
    echo "$ATTR_LINE already in .gitattributes"
fi
