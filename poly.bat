# @ECHO OFF
# GOTO :B1

# --- Bash Part ---
echo "Running in Bash"
echo "Multiline test:"
cat << EOF
Line 1
Line 2
EOF
(set -x; echo\
  one\
  two\
  three)
# -----------------

: << '::EOF'

:B1
REM -- Batch Part --
ECHO Running in Batch
ECHO Multiline test:
ECHO Line 1^
ECHO Line 2
@ECHO ON
ECHO^
  one^
  two^
  three
@ECHO OFF
REM ----------------

::EOF

echo hi
