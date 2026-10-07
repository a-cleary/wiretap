# Wiretap

Wiretap is a network intelligence engine that transforms PCAP and PCAPNG captures into structured network context.

Instead of treating a packet capture as a collection of packets, Wiretap extracts and organizes the information contained within those packets into:

- Hosts
- Hostnames
- Services
- Connections and flows
- DNS transactions
- HTTP transactions
- TLS metadata and certificates
- SMB activity
- Identities
- SMB shares
- File paths
- Relationships between entities
- Time-bounded network activity

The resulting data can be queried programmatically or emitted as JSONL for use with tools such as `jq` and other analysis pipelines.

---

## Design Philosophy

Wiretap is designed around a simple idea:

> **Packets are evidence. Network context is the product.**

A packet capture contains individual protocol messages, but analysts usually need to answer higher-level questions:

- Which hosts communicated?
- What services were observed?
- Which hostnames resolved to which addresses?
- Which hosts queried a particular hostname?
- Which identities appeared during SMB authentication?
- Which shares were accessed?
- Which paths were involved in SMB file operations?
- What relationships exist between network entities?
- When was a particular relationship observed?

Wiretap separates these concerns into several layers.

```text
PCAP / PCAPNG
      │
      ▼
Protocol Parsers
      │
      ▼
Observations
      │
      ▼
Entity Resolution
      │
      ▼
Relationships
      │
      ▼
Network Context
      │
      ├── Queries
      ├── Traversal
      ├── Timeline
      └── JSONL
```

The core architectural principle is:

> __Parsers discover facts. The knowledge model connects facts. Queries and reporting interpret context.__

Wiretap does not attempt to determine whether observed activity is malicious. It focuses on extracting and organizing network evidence so that other tools, analysts, and workflows can use it.

---

## Installation

Wiretap requires Python 3.10 or newer.

Clone the repository and install it:

```bash
git clone https://github.com/a-cleary/wiretap.git
cd wiretap

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

For development dependencies:

```bash
pip install -e ".[dev]"
```

Verify the installation:

```bash
wiretap --help
```

## Usage


Wiretap's primary workflow is to process a PCAP or PCAPNG capture and emit structured network information.

```text
PCAP → Wiretap → JSONL → jq / other tools
```

The basic command is:

```bash
wiretap capture.pcap --jsonl
```

This produces one JSON object per line.

For example:

```bash
wiretap capture.pcap --jsonl | jq
```

Filtering can then be performed with standard command-line tools:

```bash
wiretap capture.pcap --jsonl |
    jq 'select(.type == "service")'
```

Or:

```bash
wiretap capture.pcap --jsonl |
    jq 'select(.type == "relationship")'
```

Wiretap can also be used to query the network context reconstructed from the capture.

### Inspect a Host

Use `--host` to inspect the context associated with a particular IP:

```bash
wiretap capture.pcap --host 10.10.10.42
```

This includes information such as:

* The host itself
* Associated hostnames
* Observed services
* Related hosts
* Incoming relationships
* Outgoing relationships

See the Host Context section below for more information.

### Find Related Entities

Use `--related` to retrieve entities directly related to a host:

```bash
wiretap capture.pcap --related 10.10.10.42
```

Relationships can be filtered:

```bash
wiretap capture.pcap \
    --related 10.10.10.42 \
    --relation queried
```

For example, this can answer:

> Which hostnames did this host query?

Or:

```bash
wiretap capture.pcap \
    --related 10.10.10.42 \
    --relation connects_to
```

> Which hosts did this host communicate with?

### Traverse the Network Context

Wiretap can follow relationships through the reconstructed network context:

```bash
wiretap capture.pcap \
    --traverse 10.10.10.42 \
    --depth 2
```

### Combine Traversal with JSONL

Traversal results can also be emitted as JSONL:

```bash
wiretap capture.pcap \
    --traverse 10.10.10.42 \
    --depth 2 \
    --jsonl
```

This makes the traversal output directly usable in shell pipelines.

---

## Host Context

A host query provides an analyst-oriented view of a specific IP address.

```bash
wiretap capture.pcap --host 10.10.10.42
```

The result contains the host and the network context directly associated with it.

For example, a host may have:

```text
Host
├── Hostnames
├── Services
├── Related Hosts
├── Incoming Relationships
└── Outgoing Relationships
```

This is useful when starting analysis from a known IP address.

If the requested host does not exist in the capture, Wiretap reports that the host was not found.

---

## Related Entities

The `--related` option retrieves entities directly connected to a host through outgoing relationships.

```bash
wiretap capture.pcap --related 10.10.10.42
```

Relationships can be filtered with `--relation`.

For example:

```bash
wiretap capture.pcap \
    --related 10.10.10.42 \
    --relation connects_to
```

returns hosts connected to the starting host.

Similarly:

```bash
wiretap capture.pcap \
    --related 10.10.10.42 \
    --relation queried
```

returns hostnames queried by that host.

Relationship types currently include examples such as:

```text
connects_to
runs
queried
resolves_to
accessed
presented_certificate
authenticated_as
accessed_share
created_path
reads_from
writes_to
closed_path
accessed_path
```

---

## Relationship Traversal

Wiretap can perform bounded traversal through the network context reconstructed from a capture.

```bash
wiretap capture.pcap \
    --traverse 10.10.10.42 \
    --depth 2
```

Traversal starts with the specified entity and follows outgoing relationships.

For example:

```text
host:10.10.10.42
        │
        ├── connects_to ──→ host:10.10.10.20
        │                         │
        │                         └── runs ──→ service:tcp/80
        │
        └── queried ───────→ hostname:fileserver.corp.local
                                  │
                                  └── resolves_to ──→ host:10.10.10.20
```

A depth of `1` follows relationships directly connected to the starting entity.

A depth of `2` follows those relationships and then follows relationships from the newly discovered entities.

Traversal can be restricted to a specific relationship:

```bash
wiretap capture.pcap \
    --traverse 10.10.10.42 \
    --depth 2 \
    --relation connects_to
```

Traversal is bounded by the requested depth so that queries remain predictable even as the network graph grows.

---

## JSONL Output

JSONL is a first-class output format in Wiretap.

Each record is emitted as a single JSON object on its own line, making the output suitable for:

* `jq`
* Shell pipelines
* Python scripts
* Other security tooling
* Log processing systems
* Data ingestion pipelines

### Timeline Output

The standard JSONL mode produces time-ordered network records:

```bash
wiretap capture.pcap --jsonl
```

Depending on the capture, records may include:

```text
flow
dns_query
dns_transaction
http_request
http_response
http_transaction
tls_client_hello
tls_server_hello
tls_certificate
smb_negotiate
smb_session_setup
smb_tree_connect
smb_file_operation
smb_transaction
hostname
service
relationship
```

For example:

```bash
wiretap capture.pcap --jsonl |
    jq 'select(.type == "flow")'
```

Or:

```bash
wiretap capture.pcap --jsonl |
    jq 'select(.type == "dns_transaction")'
```

### Traversal JSONL

Traversal output uses --jsonl to produce entity and relationship records:

```bash
wiretap capture.pcap \
    --traverse 10.10.10.42 \
    --depth 2 \
    --jsonl
```

Entity records have this general structure:

```json
{
  "type": "entity",
  "entity_type": "host",
  "id": "host:10.10.10.20",
  "value": "10.10.10.20"
}
```

Relationship records have this general structure:

```json
{
  "type": "relationship",
  "id": "host:10.10.10.42:connects_to:host:10.10.10.20",
  "relation": "connects_to",
  "source": "host:10.10.10.42",
  "target": "host:10.10.10.20",
  "first_seen": "...",
  "last_seen": "..."
}
```

This allows traversal results to be consumed without requiring a separate graph database or API.

---

## Supported Network Data
### Network Flows

Wiretap aggregates individual connections into flows.

Flows include information such as:

* Endpoints
* Protocol
* First seen
* Last seen
* Packet count
* Byte count
* Initiator
* Responder
* Directional packet counts
* Directional byte counts

TCP connection roles are inferred from SYN/SYN-ACK behavior when available.

### DNS

Wiretap extracts DNS queries and responses and correlates them into transactions.

DNS processing includes:

* Queries
* Query types
* Transaction IDs
* Response codes
* Answers
* TTLs
* Hostname entities
* Host entities derived from A and AAAA records

DNS relationships include:

```text
host ──queried──────→ hostname
hostname ──resolves_to──→ host
```

### HTTP

Wiretap extracts HTTP requests and responses and correlates them into transactions.

#### Requests
* Source and destination
* Method
* Host
* Path
* HTTP version
* User-Agent
#### Responses
* Status code
* Reason
* Server
* Content type
* Content length
* Location

Requests and responses can be correlated into HTTP transactions.

### TLS

Wiretap extracts metadata from TLS handshakes as well as certificates.

#### ClientHello
* TLS version
* Server Name Indication
* ALPN protocols
* Cipher suites
* Source and destination
#### ServerHello
* TLS version
* Negotiated cipher suite
* ALPN protocol
#### Certificates
* SHA-256 fingerprint
* Subject
* Issuer
* Serial number
* Validity period
* Subject Alternative Names

Certificates are tracked as entities and can be connected to hosts through relationships.

### SMB

Wiretap provides protocol-level network context for SMB activity.

#### Negotiate
* SMB version
* Dialects
* Negotiated dialect
#### Session Setup
* Username
* Domain
* Workstation
* Session information
#### Tree Connect
* Share
* Share type
* Tree information
#### File Operations
* Operation
* Path
* Filename
* File identifier
* Offset
* Length
* Resolved path
* Identity
* Share

Wiretap correlates SMB state across messages to resolve relationships between identities, sessions, shares, and file paths.

For example:

``` text
Identity
    │
    ▼
SMB Session
    │
    ▼
Share
    │
    ▼
File Path
```
---

## Roadmap

Potential future work includes:

* Additional protocol parsers
* More transaction correlation
* Richer entity types
* More relationship types
* Improved query capabilities
* Filtering and projection for JSONL output
* Additional timeline analysis
* Capture statistics and summaries
* Performance improvements for larger captures
* Streaming-oriented processing
* Additional export formats
* More advanced graph queries
* Better handling of fragmented and multi-packet protocol data

The goal is to expand Wiretap's ability to reconstruct useful network context while keeping the underlying data model understandable and composable.

---

## Intended Use

Wiretap is intended for legitimate security analysis, research, education, network troubleshooting, and other authorized uses.

When analyzing network captures, ensure that you have appropriate authorization to inspect the traffic and associated data.