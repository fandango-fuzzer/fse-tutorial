# EXERCISE 2 - Semantic constraints
#
# Goal: make the messages WELL-FORMED so the server accepts them. The grammar
# from Exercise 1 is given below in full so you can focus on the constraints.
# Tie LEN and CRC to the body and bound the size; when all three hold, inputs
# get past validation and reach the handlers.
#
# Read:  docs/FDP-SPEC.md, sections 4-5 (LEN and CRC) and Appendix B (CRC algo)
# Docs:  Fandango constraints (where clauses) -> https://fandango-fuzzer.github.io/Constraints.html
# Run:   fandango fuzz -f exercises/02_constraints.fan -n 5
# Validate: python fdp_validate.py --step language --spec exercises/02_constraints.fan
#
# Verify your inputs are accepted:
#   fandango fuzz -f exercises/02_constraints.fan -n 20 --file-mode binary -d /tmp/ex2
#   for f in /tmp/ex2/*; do echo "$(cat "$f")" | python fdp_server.py; done

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

# ---------------------------------------------------------------------------
# TODO 1 (length encoding): LEN must equal the number of characters in <body>.
#   The fields are text, so compare them as strings (both sides str(...)).
#   See FDP-SPEC section 4.
# where

# TODO 2 (checksum): CRC must equal the CRC-16 of <body>. Do NOT re-derive the
#   algorithm - call the reference implementation in fdp.py (see Appendix B for
#   which helper) on the body, and compare it to <crc>.
# where

# TODO 3 (min/max): keep the body length between 1 and 64 characters.
# where
# ---------------------------------------------------------------------------

import fdp
