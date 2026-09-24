# Certadillo user guide

This guide covers everything a platform team or an application team needs to run Certadillo and get certificates from it. Every command in it was run against a live server while the guide was written.

The same pages, plus interactive 3D walkthroughs of each protocol, are served by a running Certadillo at `/kb`.

## Start here

| If you are | Read |
| --- | --- |
| New to Certadillo | [Concepts](01-concepts.md), then [Getting started](02-getting-started.md) |
| An app team that needs certificates | [Onboarding](03-onboarding.md), then the page for your protocol |
| Running the platform | [Administration](15-administration.md), [Alerting and observability](13-alerting-observability.md), the [runbook](../RUNBOOK.md) |

## Protocols

Pick the protocol your client already speaks. They all go through the same onboarding, policy checks and audit trail.

| Page | Use it for |
| --- | --- |
| [REST API and CLI](04-rest-api.md) | Scripts, pipelines, anything you control end to end |
| [ACME](05-acme.md) | Web servers and Kubernetes: certbot, cert-manager, lego, acme.sh, win-acme |
| [EST](06-est.md) | Devices and appliances that support RFC 7030 (ATMs, IoT, newer network gear) |
| [SCEP](07-scep.md) | MDM-managed devices (Intune, Jamf), routers, VPN concentrators, legacy appliances |
| [CMP](18-cmp.md) | Telecom and industrial equipment that speaks RFC 9483 lightweight CMP |
| [SSH certificates](08-ssh.md) | Short-lived user and host certificates for OpenSSH |
| [Workload identity (SPIFFE)](09-workload-identity.md) | Service-to-service mTLS with SPIFFE IDs |
| [Code signing and S/MIME](10-code-signing-smime.md) | Release signing (with dual control) and email certificates |

## Operating it

- [Revocation: OCSP and CRL](11-revocation.md)
- [Renewal campaigns: planned early renewal before a mass revocation](19-renewal-campaigns.md)
- [Discovery and inventory](12-discovery-inventory.md)
- [Alerting and observability](13-alerting-observability.md)
- [Automation: CLI, Ansible, PowerShell, CI](14-automation.md)
- [Administration: roles, approvals, CAs, HSM, configuration](15-administration.md)
- [API reference](16-api-reference.md)
- [Troubleshooting and policy errors](17-troubleshooting.md)
