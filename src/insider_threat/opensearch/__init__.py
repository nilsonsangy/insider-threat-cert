"""insider_threat.opensearch: loading the CERT r4.2 sources into OpenSearch.

- ``mappings``: indices, columns and explicit field types.
- ``bulk``: HTTP transport, index lifecycle and the _bulk API.
- ``resume``: checkpoint and byte offsets to continue an interrupted load.
- ``derived``: documents of the derived indices (cert-copy-daily, cert-risk).
- ``ingest``: streaming of each source and of the derived indices.

Only the standard library is used for HTTP.
"""