: #!/bin/sh
wgo -xdir . npx @tailwindcss/cli --input ./static/notebrew.css --output ./static/notebrew.min.css --watch=always :: wgo -xdir . npx esbuild ./static/notebrew.js --bundle --outfile=./static/notebrew.min.js --watch=forever :: wgo -verbose -file .go go install -tags dev ./notebrew :: notebrew
