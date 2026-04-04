: #!/bin/sh
: # This script works in both cmd.exe and sh.
: # https://stackoverflow.com/a/17623721

:<<'::STOP'

@echo off
set CGO_ENABLED=0
wgo -xdir . npx @tailwindcss/cli --input ./static/notebrew.css --output ./static/notebrew.min.css --watch=always :: wgo -xdir . npx esbuild ./static/notebrew.js --bundle --outfile=./static/notebrew.min.js --watch=forever :: wgo -verbose -file .go go install -tags dev ./notebrew :: notebrew
goto :END

::STOP

CGO_ENABLED=0 wgo -xdir . npx @tailwindcss/cli --input ./static/notebrew.css --output ./static/notebrew.min.css --watch=always :: wgo -xdir . npx esbuild ./static/notebrew.js --bundle --outfile=./static/notebrew.min.js --watch=forever :: wgo -verbose -file .go go install -tags dev ./notebrew :: notebrew
exit $?

:END
