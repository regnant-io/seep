`cordon-client.crt` / `cordon-client.key` are a throwaway self-signed
certificate (CN=seep-test-client) used only by the unit tests that load a
Cordon mutual-TLS identity. They protect nothing and are trusted by nothing.
