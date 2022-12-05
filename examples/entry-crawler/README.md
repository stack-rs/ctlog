# entry-crawler

A simple example shows crawling all entries from one log server and saving them to a JSON file.

## Usage

```bash
cargo run --example entry-crawler -- -u <url of log server> -o <output JSON file>
```

## Example

```bash
cargo run --example entry-crawler -- -u "https://ct2024.trustasia.com/log2024/" -o trustasia2024.json
```

First two entries of `trustasia2024.json`:

```json
{
  "index": 0,
  "is_precert": true,
  "version": "V3",
  "is_ca": false,
  "cn": "p49xh95dcg.ct-test.ssl.pub",
  "sans": [
    "DNSName(p49xh95dcg.ct-test.ssl.pub)"
  ],
  "icn": "TrustAsia DV TLS RSA Test CA G3",
  "serial": "20:20:78:8a:0c:fb:42:d5:93:b0:32:55:62:be:1c:f8:eb:1b:34:5c",
  "not_before": "2023-12-31 16:00:00.0 +00:00:00",
  "not_after": "2024-01-31 16:00:00.0 +00:00:00",
  "issue_at": "2022-09-30 01:45:56.759 UTC",
  "raw_extensions": [
    {
      "oid": "basicConstraints (2.5.29.19)",
      "critical": true,
      "value": "30:00:"
    },
    {
      "oid": "authorityKeyIdentifier (2.5.29.35)",
      "critical": false,
      "value": "30:16:80:14:1b:2f:8b:fb:f1:2a:cb:6e:4d:fd:26:40:c0:36:a9:18:82:a2:aa:e9:"
    },
    {
      "oid": "authorityInfoAccess (1.3.6.1.5.5.7.1.1)",
      "critical": false,
      "value": "30:81:95:30:4a:06:08:2b:06:01:05:05:07:30:02:86:3e:68:74:74:70:3a:2f:2f:69:63:61:2e:77:74:2d:74:65:73:74:2e:74:72:75:73:74:61:73:69:61:2e:63:6f:6d:2f:54:72:75:73:74:41:73:69:61:44:56:54:4c:53:52:53:41:54:65:73:74:43:41:47:33:2e:63:72:74:30:47:06:08:2b:06:01:05:05:07:30:01:86:3b:68:74:74:70:3a:2f:2f:6f:63:73:70:2e:77:74:2d:74:65:73:74:2e:74:72:75:73:74:61:73:69:61:2e:63:6f:6d:2f:54:72:75:73:74:41:73:69:61:44:56:54:4c:53:52:53:41:54:65:73:74:43:41:47:33:"
    },
    {
      "oid": "subjectAltName (2.5.29.17)",
      "critical": false,
      "value": "30:1c:82:1a:70:34:39:78:68:39:35:64:63:67:2e:63:74:2d:74:65:73:74:2e:73:73:6c:2e:70:75:62:"
    },
    {
      "oid": "certificatePolicies (2.5.29.32)",
      "critical": false,
      "value": "30:0a:30:08:06:06:67:81:0c:01:02:01:"
    },
    {
      "oid": "extendedKeyUsage (2.5.29.37)",
      "critical": false,
      "value": "30:14:06:08:2b:06:01:05:05:07:03:02:06:08:2b:06:01:05:05:07:03:01:"
    },
    {
      "oid": "crlDistributionPoints (2.5.29.31)",
      "critical": false,
      "value": "30:46:30:44:a0:42:a0:40:86:3e:68:74:74:70:3a:2f:2f:63:72:6c:2e:77:74:2d:74:65:73:74:2e:74:72:75:73:74:61:73:69:61:2e:63:6f:6d:2f:54:72:75:73:74:41:73:69:61:44:56:54:4c:53:52:53:41:54:65:73:74:43:41:47:33:2e:63:72:6c:"
    },
    {
      "oid": "subjectKeyIdentifier (2.5.29.14)",
      "critical": false,
      "value": "04:14:a7:4f:be:62:00:d1:f3:89:ad:23:a9:af:c5:cb:c1:62:6b:51:bc:2f:"
    },
    {
      "oid": "keyUsage (2.5.29.15)",
      "critical": true,
      "value": "03:02:05:a0:"
    }
  ]
},
{
  "index": 1,
  "is_precert": true,
  "version": "V3",
  "is_ca": false,
  "cn": "jej7adhe6q.ct-test.ssl.pub",
  "sans": [
    "DNSName(jej7adhe6q.ct-test.ssl.pub)"
  ],
  "icn": "TrustAsia DV TLS ECC Test CA G4",
  "serial": "10:07:0b:6f:38:8d:0b:48:73:05:aa:c4:40:29:6a:8f:39:8a:52:c1",
  "not_before": "2023-12-31 16:00:00.0 +00:00:00",
  "not_after": "2024-03-31 16:00:00.0 +00:00:00",
  "issue_at": "2022-09-30 05:21:53.308 UTC",
  "raw_extensions": [
    {
      "oid": "basicConstraints (2.5.29.19)",
      "critical": true,
      "value": "30:00:"
    },
    {
      "oid": "authorityKeyIdentifier (2.5.29.35)",
      "critical": false,
      "value": "30:16:80:14:af:84:b5:74:27:70:df:14:a7:2a:cc:3a:5a:dc:f7:3c:04:09:53:9b:"
    },
    {
      "oid": "authorityInfoAccess (1.3.6.1.5.5.7.1.1)",
      "critical": false,
      "value": "30:81:95:30:4a:06:08:2b:06:01:05:05:07:30:02:86:3e:68:74:74:70:3a:2f:2f:69:63:61:2e:77:74:2d:74:65:73:74:2e:74:72:75:73:74:61:73:69:61:2e:63:6f:6d:2f:54:72:75:73:74:41:73:69:61:44:56:54:4c:53:45:43:43:54:65:73:74:43:41:47:34:2e:63:72:74:30:47:06:08:2b:06:01:05:05:07:30:01:86:3b:68:74:74:70:3a:2f:2f:6f:63:73:70:2e:77:74:2d:74:65:73:74:2e:74:72:75:73:74:61:73:69:61:2e:63:6f:6d:2f:54:72:75:73:74:41:73:69:61:44:56:54:4c:53:45:43:43:54:65:73:74:43:41:47:34:"
    },
    {
      "oid": "subjectAltName (2.5.29.17)",
      "critical": false,
      "value": "30:1c:82:1a:6a:65:6a:37:61:64:68:65:36:71:2e:63:74:2d:74:65:73:74:2e:73:73:6c:2e:70:75:62:"
    },
    {
      "oid": "certificatePolicies (2.5.29.32)",
      "critical": false,
      "value": "30:0a:30:08:06:06:67:81:0c:01:02:01:"
    },
    {
      "oid": "extendedKeyUsage (2.5.29.37)",
      "critical": false,
      "value": "30:14:06:08:2b:06:01:05:05:07:03:02:06:08:2b:06:01:05:05:07:03:01:"
    },
    {
      "oid": "crlDistributionPoints (2.5.29.31)",
      "critical": false,
      "value": "30:46:30:44:a0:42:a0:40:86:3e:68:74:74:70:3a:2f:2f:63:72:6c:2e:77:74:2d:74:65:73:74:2e:74:72:75:73:74:61:73:69:61:2e:63:6f:6d:2f:54:72:75:73:74:41:73:69:61:44:56:54:4c:53:45:43:43:54:65:73:74:43:41:47:34:2e:63:72:6c:"
    },
    {
      "oid": "subjectKeyIdentifier (2.5.29.14)",
      "critical": false,
      "value": "04:14:0f:e1:97:a7:6c:f6:2a:88:1c:6c:21:14:7f:1f:6d:ea:c8:56:66:07:"
    },
    {
      "oid": "keyUsage (2.5.29.15)",
      "critical": true,
      "value": "03:02:05:a0:"
    }
  ]
},
```
