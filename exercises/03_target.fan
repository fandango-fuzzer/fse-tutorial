# EXERCISE 3b - Execution feedback: hit a specific branch
#
# Goal: directed testing. Add ONE execution-feedback constraint that forces
# every input to drive the target through a chosen branch. fdp_cover has a
# helper that runs a message and checks the target's branch trace for a given
# label - find it in fdp_cover.py.
#
# Read:  fdp_cover.py, and the branch labels in fdp.py (grep for _mark)
# Docs:  the feedback here is a where-constraint in Python -> https://fandango-fuzzer.github.io/Constraints.html
# Run:   fandango fuzz -f exercises/03_target.fan -n 5
# Validate: python fdp_validate.py --step feedback --spec exercises/03_coverage.fan
#           (grades the feedback block via 3a. This directed variant has no
#           coverage grade of its own - your check here is the Run output
#           itself: every generated line must be a LOGIN.)
#
# Once it works, try steering to different branch labels and watch the output
# change:  "apply:login" yields only LOGINs, "apply:pong" only PINGs. fdp_cover
# also has a helper for constraining on the server's reply code instead (e.g.
# require "ERR_NOAUTH") - that turns this into negative testing.

<start>   ::= <message>
<message> ::= <ver> " " <body> " LEN=" <len> " CRC=" <crc>

<ver>     ::= "FDP1" | "FDP2"

<body>      ::= <login> | <message_msg> | <subscribe> | "PING" | "QUIT"
<login>       ::= "LOGIN user=" <name> <passopt>
<passopt>     ::= "&pass=" <word> | ""
<message_msg> ::= "MSG to=" <name> "&body=" <text>
<subscribe>   ::= "SUB chan=" <name>

<len>     ::= <digit>+
<crc>     ::= <hex>{4}

<name>    ::= r'[a-z]+'
<word>    ::= r'[a-z0-9]+'
<text>    ::= r'[a-z0-9 ]+'
<digit>   ::= r'[0-9]'
<hex>     ::= r'[0-9a-f]'

# well-formedness (from Exercise 2, given)
where str(<len>) == str(len(str(<body>)))
where str(<crc>) == fdp.crc16hex(str(<body>))
where 1 <= len(str(<body>)) <= 64

# ---------------------------------------------------------------------------
# TODO (execution feedback): demand each input execute the "apply:login"
#   branch of the target. Use the fdp_cover helper that checks whether a message
#   reaches a given branch label, passing the whole message line and that label.
# where
# ---------------------------------------------------------------------------

import fdp
import fdp_cover
