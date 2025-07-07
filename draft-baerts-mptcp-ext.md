---
title: "Multipath TCP with external keys"
category: std

docname: draft-baerts-mptcp-ext-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Transport"
workgroup: "TCPM"
keyword:
 - mptcp
venue:
  group: "TCPM"
  type: "Individual"
  mail: "tcpm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tcpm/"
  github: "IPNetworkingLab/draft-mptcp-ext"
  latest: "https://ipnetworkinglab.github.io/draft-mptcp-ext/draft-baerts-mptcp-ext.html"

author:
 -
    fullname: Matthieu Baerts
    organization: UCLouvain
    email: matthieu.baerts@uclouvain.be
 -
    fullname: Olivier Bonaventure
    organization: UCLouvain & WELRI
    email: olivier.bonaventure@uclouvain.be

normative:
  RFC8684:

informative:
 RFC6181:
 RFC8446:
 RFC4253:

--- abstract

This document proposes an extension to Multipath TCP that allows application
layer protocols such as TLS or SSH to provide keys to authenticate the creation
of new subflows.


--- middle

# Introduction

This document addresses an important limitation of Multipath TCP {{RFC8684}}:
the exchange of plain text keys during the handshake.

From a security viewpoint, Multipath TCP is vulnerable to on-path attacks
{{RFC6181}}. Since Multipath TCP relies on keys that are exchanged in clear
during the handshake, an on-path attacker can easily collect the authentication
keys and later establish a subflow on an existing Multipath TCP connection. If
this connection is used to support secure protocols such as TLS {{RFC8446}} or
SSH {{RFC4253}}, the attacker will only be able to disrupt the connection.

This document proposes a modification to the MP_CAPABLE and MP_JOIN options that
enables Multipath TCP hosts to use keys that are derived by upper layer
protocols such as TLS or SSH. This idea has already been discussed in the past
{{?I-D.paasch-mptcp-ssl-00}},
{{?I-D.paasch-mptcp-application-authentication-00}} and
{{?I-D.paasch-mptcp-tls-authentication-00}}. We provide an overview of this
extension in {{overview}} and describe the protocol modifications in
{{changes}}.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Protocol overview {#overview}

This document proposes an extension that allows Multipath TCP to use either a
pre-configured key or a key derived by an upper layer security protocol to
authenticate the advertisement of additional addresses, the establishment of new
subflows, and the abrupt closure of a whole connection. This extension is
negotiated during the establishment of the Multipath TCP connection by setting
the TBD bit in the MP_CAPABLE option. This is illustrated in
{{fig-e-handshake}}.


~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Host A                                  Host B
   ------                                  ------
   MP_CAPABLE                ->
   [flags (TBD is set)]
                             <-            MP_CAPABLE
                                           [B's token, flags (TBD is set)]
   ACK + MP_CAPABLE (+ data) ->
   [A's token, B's token, flags, (data-level details)]
~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-e-handshake title="Negotiation of the utilization of external keys"}

If the TBD flag is set and the responder supports the option, it returns an
MP_CAPABLE that contains the 32-bit token that it uses to identify this
connection. The connection initiator replies with an MP_CAPABLE option
containing its 32-bit token and the remote 32-bit token.

This modification has two important advantages compared to Multipath TCP version
1 {{RFC8684}}. First, the MP_CAPABLE option is shorter. It contains only two
32-bit tokens instead of two 64-bit keys in the third ACK. Second, the token is
not derived from a random key using a hash function. This implies that there is
no risk of collision between a new key and a token used for an existing
connection. The token must uniquely identify the associated connection and
should be selected randomly {{!RFC4086}}.

After the handshake, host A and host B cannot create additional subflows or
exchange additional addresses. These operations can only occur once they have
agreed on an external key. Once a host has learned an external key (e.g. through
configuration, socket option, or derived from a security protocol), it SHOULD
inform the other by sending a hash of this key in a NEW_KEY option a shown in
{{fig-newkey-ex}}. The key is installed once a host has received a hash of the
key from the other host.

Security protocols need to change keys regularly for security reasons. Multipath
TCP version 1 {{RFC8684}} does not support changing the security keys. This
extension uses a key identifier to support key changes. All authenticated
options contain the K bit which is the identifier of the key used to
authenticate it. The initial external key corresponds to identifier 0.

~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Host A                                  Host B
   ------                                  ------
   NEW_KEY [K,hash(ExtKey)]         ->

                                  <-       NEW_KEY[K,hash(ExtKey)]

~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-newkey-ex title="Confirmation of the utilization of a new external key"}

The key identifier is included in the modified ADD_ADDR, MP_JOIN and FASTCLOSE
options described later in this document.

# Changes to Multipath TCP {#changes}

This section describes the changes to the Multipath TCP options that are
required to support external keys.

## Extending the MP_CAPABLE and MP_JOIN options {#mpc}

{{RFC8684}} defines the MP_CAPABLE option as shown in {{fig-oldmpc}}.

~~~~~~~~~~~~~~~~~~~~~~~~~~~
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------+---------------+-------+-------+---------------+
     |     Kind      |    Length     |Subtype|Version|A|B|C|D|E|F|G|H|
     +---------------+---------------+-------+-------+---------------+
     |                   Option Sender's Key (64 bits)               |
     |                      (if option Length > 4)                   |
     |                                                               |
     +---------------------------------------------------------------+
     |                  Option Receiver's Key (64 bits)              |
     |                      (if option Length > 12)                  |
     |                                                               |
     +-------------------------------+-------------------------------+
     |  Data-Level Length (16 bits)  |  Checksum (16 bits, optional) |
     +-------------------------------+-------------------------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-oldmpc title="The MP_CAPABLE option in RFC8684"}

This option contains several flags, A-H. Flags A, B, C, and H are specified in
{{RFC8684}}. This document changes the TBD Flag. If this Flag is set in a SYN,
this indicates the utilization of external keys. An external key is a key which
is either known, e.g. by configuration as a shared secret, or derived from a
negotiated secure key, e.g. by protocols such as SSH or TLS. This key is used as
an authentication key for the establishment of additional subflows.

A Multipath TCP implementation maintains two 64-bit keys:

- a local key chosen by the host and exchanged during the handshake
- a remote key learned during the handshake

As specified in {{RFC8684}}, a local 32-bit token and a remote 32-bit token are
derived from these keys. The keys and the token are known at the end of the
handshake.

When the external keys are used, the situation is different. The connection
initiator sends an empty MP_CAPABLE option in its SYN segment. A responder that
receives a SYN with the MP_CAPABLE option having the TBD bit set responds with
an MP_CAPABLE option and the TBD bit set if it supports the external keys.
Otherwise, it replies with an MP_CAPABLE option whose TBD bit is reset and
follows the procedure defined in {{RFC8684}}.

If the responder replies with an MP_CAPABLE option whose TBD Flag is set, the
option in the SYN+ACK contains the 32-bit token that it uses to identify this
connection.

Upon reception of the SYN+ACK, the connection initiator replies with a third ACK
that contains an MP_CAPABLE option with the TBD bit set. This option contains
the initiator and the responder tokens.

~~~~~~~~~~~~~~~~~~~~~~~~~~~
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------+---------------+-------+-------+---------------+
     |     Kind      |    Length     |Subtype|Version|A|B|C|D|E|F|G|H|
     +---------------+---------------+-------+-------+---------------+
     |                   Option Sender's Token (32 bits)             |
     |                      (if option Length > 4)                   |
     +---------------------------------------------------------------+
     |                  Option Receiver's Token (32 bits)            |
     |                      (if option Length > 8)                   |
     +-------------------------------+-------------------------------+
     |  Data-Level Length (16 bits)  |  Checksum (16 bits, optional) |
     +-------------------------------+-------------------------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-newmpc title="The modified MP_CAPABLE option"}


If the TBD bit was set in the MP_CAPABLE option of the SYN+ACK, this indicates
that there are no security keys associated with the connection. This implies
that it is impossible to advertise addresses or join an additional subflow until
external keys have been exchanged.

## Changing the external key

Once the Multipath TCP connection has been established, the applications can
decide to use an external key.

Once the hosts have agreed on an external key to use to authenticate the
MP_JOIN, ADD_ADDR, and MP_FASTCLOSE options on a connection, they inform the
other host by sending a NEW_KEY option. This option is shown in {{fig-newkey}}.

~~~~~~~~~~~~~~~~~~~~~~~~~~~
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------+---------------+-------+-----+-+---------------+
     |  NEW_KEY      |  Length = 12  |Subtype|(rsv)|K|       0       |
     +---------------+---------------+-------+-----+-+---------------+
     |               Low order HMAC of the external key              |
     |                           (64 bits)                           |
     +---------------------------------------------------------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-newkey title="The NEW_KEY option"}


This new option contains two pieces of information:

 - a one-bit key identifier (K)
 - a 64-bit HMAC of the external key

The key identifier identifies the last key exchanged on a connection. The key
identifiers start at 0, i.e. the first NEW_KEY option contains the K bit set to
zero. The 64-bit HMAC contains the low order 64 bits of a HMAC of the external
key computed using the negotiated hash algorithm. The key for this HMAC, in the
case of a message transmitted by Host A, is Token-A followed by Token-B; and in
the case of Host B, Key-B followed by Key-A. The "message" for the HMAC
algorithm in each case is the external key.

Once a host has sent a NEW_KEY option, it SHOULD start a timer. If it does not
receive an option containing the same hash value, it should retransmit the
option.

A host must store two external keys:

- the current one
- the next key

A key is considered to be active once a host has received a NEW_KEY option
containing a HMAC of this key. If a host receives a NEW_KEY option whose HMAC
and key identifier do not match the stored ones, it simply discards the option.

## Using the external key

While Multipath TCP version 1 uses two different keys announced by the
communicating hosts, the external key is a key shared by both hosts. {{RFC8684}}
defined several procedures that rely on these two keys to authenticate the
establishment of subflows using the MP_JOIN option, the advertisement for new
addresses, or the fast termination of a connection.

These procedures change with an external key. The first modification is that
these options now contain a K bit that indicates the identifier of the external
key used to (request to) authenticate the option. The second modification is
that instead of computing HMACs over KeyA||KeyB, the HMACs defined in
{{RFC8684}} are now computed using the external key whose identifier is K.

The new format of the MP_JOIN option is shown in {{fig-newmpjoin}}.

~~~~~~~~~~~~~~~~~~~~~~~~~~~
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------+---------------+-------+-----+-+---------------+
     |     Kind      |  Length = 12  |Subtype|(r)|K|B|   Address ID  |
     +---------------+---------------+-------+-----+-+---------------+
     |                   Receiver's Token (32 bits)                  |
     +---------------------------------------------------------------+
     |                Sender's Random Number (32 bits)               |
     +---------------------------------------------------------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-newmpjoin title="The modified MP_JOIN option"}


The new format of the ADD_ADDR option is shown in {{fig-newaddr}}.

~~~~~~~~~~~~~~~~~~~~~~~~~~~
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +---------------+---------------+-------+-------+---------------+
  |     Kind      |     Length    |Subtype|(r)|K|E|  Address ID   |
  +---------------+---------------+-------+-------+---------------+
  |           Address (IPv4: 4 octets / IPv6: 16 octets)          |
  +-------------------------------+-------------------------------+
  |   Port (2 octets, optional)   |                               |
  +-------------------------------+                               |
  |                Truncated HMAC (8 octets, if E=0)              |
  |                               +-------------------------------+
  |                               |
  +-------------------------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-newaddr title="The modified ADD_ADDR option"}

The modified format of the MP_FASTCLOSE option is shown in {{fig-fclose}}. This
option does no longer contain the receivers' key as in {{RFC8684}}. Instead, it
contains a truncated HMAC of the external key. The key for this HMAC is, in the
case of a message transmitted by Host A, Token-A followed by Token-B; and in the
case of Host B, Token-B followed by Token-A. The "message" for the HMAC
algorithm is, in each case, the external key. The K bit indicates the
corresponding key identifier.

A host can still reset an MPTCP connection before the initial external keys got
exchanged, while there is only one subflow then. This SHOULD be done by sending
a TCP RST.


~~~~~~~~~~~~~~~~~~~~~~~~~~~
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +---------------+---------------+-------+-----------------------+
  |     Kind      |    Length     |Subtype|(rsv)|K|  (reserved)   |
  +---------------+---------------+-------+-----------------------+
  |                         Truncated HMAC                        |
  |                            (64 bits)                          |
  +---------------------------------------------------------------+

~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-fclose title="The modified MP_FASTCLOSE option"}


# Security Considerations

The solution proposed in this document aims at preventing the attacks where an
on-path attacker observes the keys associated with a Multipath TCP connection.
Since these keys are not exposed anymore, attackers cannot use them to add
subflows to an existing Multipath TCP connection.


# IANA Considerations

This document requests the IANA to reserve flag TBD of the MP_CAPABLE option as
defined in this document. It proposes to use the E flag. It also proposes to add
the K bit to the MP_JOIN, ADD_ADDR, and MP_FASTCLOSE options. Finally, it
defines the NEW_KEY option. Subtype 0x9 is suggested for this option.


--- back

# Acknowledgments
{:numbered="false"}

This work was supported by the Walloon government within the FRFS-WEL-T SEEIP
project. The idea of using external keys to secure Multipath TCP was initially
proposed in {{I-D.paasch-mptcp-ssl-00}}.
