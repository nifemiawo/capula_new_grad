
# Running the Proram and Demo

To run the demo you can either use the provided shell script (`run.sh`) or use the following commands.
In one terminal run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn server.src.main:app --reload
```

In another terminal run:

```bash
python -m demo.demo email@example.com my-master-password
```
Where the command line arguments can be replaced with your own custom username and password



## Key Assumptions and Implementation Choices With Their Trade-offs


### Running Over HTTP and How To Run Over HTTPS

The server runs over plain HTTP locally rather than TLS. This leaves the user's email address and encrypted vault blob visible to any network observer, along with the fact that a particular email is communicating with the service at all. In a deployed environment, to run the implementation over TLS I would run uvicorn behind a reverse proxy that terminates TLS using a certificate from Let's Encrypt, forwarding the decrypted request to uvicorn over plain HTTP on localhost.


### Rejection of replayed requests

The specification calls for the rejection of replayed requests. To enforce this I chose a monotonic per-account counter over possible alternatives like a set of previously-seen nonces, because it was the cheapest solution to implement and reason about, and it held for the usage pattern I assumed. I assume for the purposes of my implementation that there is only one active client acting sequentially per account. The defense mechanism chosen works for this assumption but may fail for anything that deviates away from it.

The trade-off shows up against the alternatives I didn't pick. A set of previously-seen nonces would let the client use any nonce in any order and support multiple devices, at the cost of storage that grows forever unless entries expire (which then needs a timestamp anyway). A timestamp-plus-tolerance-window scheme tolerates reordering and multiple devices much better with bounded storage, but requires synchronized clocks and a window size that's itself a security/usability judgment call.

The main limitation of this approach is that if the client's local nonce file is ever lost, there is no way to recover. The client will keep emitting nonces the server has already consumed and get rejected indefinitely, and two devices sharing a single account can't be reconciled, since each keeps an independent counter.

I also found that my original check-and-advance logic wasn't atomic. The nonce check and the update to `last_nonce` were two separate steps with no lock between them, leaving a race condition under concurrent requests for the same account. I fixed this by combining both into a single conditional `UPDATE ... WHERE last_nonce < :n`, so only one of two racing requests can match the row and succeed.

### Public Key Representation

The client sends the public key as raw 32-byte bytes, base64-encoded within the registration payload, rather than a more common interchange format like PEM. I chose this because both sides already agree the key is Ed25519, so there is nothing to encode beyond the key itself, and it keeps the overall payload structure small and the encode and decode logic much simpler.

The trade-off is that sending raw bytes gives no information about what type of key they are. For now this is fine, since both client and server hardcode the assumption that the algorithm used is always Ed25519. But if the system ever needed to support more than one algorithm, the server would have no way to tell which algorithm a given key belongs to just from the bytes, and would need an extra field added to the schema to say so explicitly. An interchange format like PEM avoids this because it encodes the algorithm alongside the key, so the server can read it off directly. I judged this unnecessary here, since the exercise fixes the algorithm to Ed25519 throughout, and it works for the application's current use case.

### Costructing Signed Data 

The signed message is the JSON serialisation of `{"email": ..., "payload": ..., "nonce": ...}`, with keys sorted and compact separators, rather tha signing the envelope fields concatenated some other way.  I chose to sign the same three fields that get echoed back in the envelope so that verification on the server is a direct reconstruction of what the client built, with no separate canonical form to keep in sync. The payload field is signed as its base64 string rather than the decoded bytes, which means the signature is technically over the encoding rather than the content, but since base64 encoding is deterministic for a given byte string this doesn't weaken anything in practice, and avoids the server needing to decode before verifying.


### Data storage

I used SQLite via SQLModel, with two tables (`User` and `Vault`), rather than a document store or an in-memory store with manual persistence. SQLite gives durability across restarts, and I wrote tests to ensure this behaviour. The main advantage of SQLite is that it gives this persistence with negligible operational overhead for an application of this size. SQLModel's typed models also keep the schema and the FastAPI request/response models sharing a similar declarative style. The tables have a one-to-one relationship, enforced by using `user_id` as both the foreign key and the primary key on `Vault`, so each user can have at most one stored vault row rather than a history of several. This implementation decision was because I interpreted "backup" as a user only having one backup vault. A new `/store` call overwrites that row in place rather than inserting a new one, keeping the schema trivial. The trade-off is that there's no way to recover from an accidental store of bad or corrupted vault data, since the previous version is gone as soon as the new one commits. In a production system this would need to be handled explicitly, either through recovery logic (e.g. retaining a short history of previous vault versions, or a soft-delete window before old data is actually purged) or through a different schema altogether that stores versions as separate rows rather than overwriting a single one.
### Mocked Verification Code Returned in API Response

Since email verification is mocked in this implementation, `/register` returns the verification code in a JSON respons rather than sending it out of band. In a real production environment this would not be acceptable as the verification code can easily be intercepted by attackers. A real implementation would deliver the code via a secure email service.


### API Structure

I structured the API as separate endpoints (`/register`, `/verify`, `/store`, `/retrieve`) rather than a single generic endpoint that dispatches on the type field inside the payload. I preferred this approach for general readability and separation of concerns. Each endpoint declares its own expected payload schema at the FastAPI routing layer rather than validating the type first and branching manually inside a single endpoint. This also makes HTTP level routing, and any future additions to the application like rate-limiting per endpoint much easier to implement without having to refactor lots of code.


