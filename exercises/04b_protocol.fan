# EXERCISE 4b - Interactive protocol fuzzing (fandango talk)
#
# Goal: turn the session into a live, two-party interaction. Fandango plays the
# client; fdp_server.py is the server. <In:x> is a message Fandango SENDS;
# <Out:y> is a reply it RECEIVES and must match. All the message and reply
# rules and constraints are given; you write the interaction itself.
#
# Read:  docs/FDP-SPEC.md, section 7; README.md ("The live protocol demo")
# Docs:  party communication (talk) -> https://fandango-fuzzer.github.io/Parties.html
# Run:   fandango -v talk -f exercises/04b_protocol.fan -n 1 python fdp_server.py

# When it works, the whole conversation is logged as it progresses:
#
#     In:  <login>    'FDP1 LOGIN user=... LEN=... CRC=...'
#     Out: <ok_login> 'OK_LOGIN ...'
#     ...             (the SUB and MSG exchanges)
#     Out: <ok_quit>  'OK_QUIT delivered=1'
#
# A WARNING about "population size reduced to 1" is expected and harmless.

# Info:
# If the server's reply does not match the <Out:...> you predicted, Fandango
# stops with "Could not parse received message fragments". Look for the
# "Received messages:" line in that error: it shows what the server actually
# said (e.g. an ERR_* code) - that reply is your bug report.

# Validate: python fdp_validate.py --step protocol --spec exercises/04a_session.fan
#           (grades the protocol block via 4a, the measurement form. This live
#           variant is checked by the conversation above completing.)

# ---------------------------------------------------------------------------
# TODO: define <start> as the exchange, alternating what Fandango SENDS and what
#       the server REPLIES, in this order:
#
#         -> login   <- ok_login
#         -> sub     <- ok_sub
#         -> msg     <- ok_msg
#         -> quit    <- ok_quit
#
#       A sent message wraps its nonterminal in <In:...>; an expected reply
#       wraps its nonterminal in <Out:...>. The message and reply nonterminals
#       are all defined below.
# <start> ::=
# ---------------------------------------------------------------------------

<login> ::= "FDP1 " <b_login> " LEN=" <l1> " CRC=" <c1> "\n"
<sub>   ::= "FDP1 " <b_sub>   " LEN=" <l2> " CRC=" <c2> "\n"
<msg>   ::= "FDP1 " <b_msg>   " LEN=" <l3> " CRC=" <c3> "\n"
<quit>  ::= "FDP1 " <b_quit>  " LEN=" <l4> " CRC=" <c4> "\n"

<b_login> ::= "LOGIN user=" <name>
<b_sub>   ::= "SUB chan=" <chan>
<b_msg>   ::= "MSG to=" <dest> "&body=" <text>
<b_quit>  ::= "QUIT"

<ok_login> ::= "OK_LOGIN " <rest> "\n"
<ok_sub>   ::= "OK_SUB " <rest> "\n"
<ok_msg>   ::= "OK_MSG " <rest> "\n"
<ok_quit>  ::= "OK_QUIT " <rest> "\n"
<rest>     ::= r'[^\n]*'

<name> ::= r'[a-z]+'
<chan> ::= r'[a-z]+'
<dest> ::= r'[a-z]+'
<text> ::= r'[a-z0-9 ]+'
<l1> ::= <digit>+
<l2> ::= <digit>+
<l3> ::= <digit>+
<l4> ::= <digit>+
<c1> ::= <hex>{4}
<c2> ::= <hex>{4}
<c3> ::= <hex>{4}
<c4> ::= <hex>{4}
<digit> ::= r'[0-9]'
<hex>   ::= r'[0-9a-f]'

# per-message length + checksum (given)
where str(<l1>) == str(len(str(<b_login>)))
where str(<c1>) == fdp.crc16hex(str(<b_login>))
where str(<l2>) == str(len(str(<b_sub>)))
where str(<c2>) == fdp.crc16hex(str(<b_sub>))
where str(<l3>) == str(len(str(<b_msg>)))
where str(<c3>) == fdp.crc16hex(str(<b_msg>))
where str(<l4>) == str(len(str(<b_quit>)))
where str(<c4>) == fdp.crc16hex(str(<b_quit>))

# min/max (as in stage 2, given): keep every body within the server's
# accepted window. (<b_quit> is the constant "QUIT", nothing to bound.)
where 1 <= len(str(<b_login>)) <= 64
where 1 <= len(str(<b_sub>)) <= 64
where 1 <= len(str(<b_msg>)) <= 64

# stateful cross-message constraint (given)
where str(<dest>) == str(<chan>)

import fdp
