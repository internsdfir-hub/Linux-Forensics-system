Linux Forensic Analyzer (LFA) - Portable Examiner Build
=======================================================

Self-contained. No installation, no admin rights, no network.
Copy this folder anywhere (local disk, USB, network share) and run it.

FIRST RUN
  Double-click verify-install.cmd. It should print 'OK'.

ANALYSE AN EVIDENCE BUNDLE
  Open a terminal in this folder, then:
    lfa.cmd analyse --case-dir cases\CASE-001 C:\path\to\bundle.tar.gz
    lfa.cmd verify  cases\CASE-001
    lfa.cmd report  cases\CASE-001
  The report is written to cases\CASE-001\report.html (opens in any browser).

WEB DASHBOARD (reviewing cases on this machine)
  Double-click lfa-dashboard.cmd, then browse to:
    http://127.0.0.1:8443
  Binds to loopback only - nothing is exposed to the network.

RECEIVING EVIDENCE STREAMED FROM A LINUX TARGET
  lfa-server.cmd <token> [port]
  Binds 0.0.0.0 so the target can reach it. On the Linux host:
    sudo sh collect.sh -c CASE-01 -p Bob -M \
         -s http://<this-windows-host>:8443 -T <token>
  The collector appends /api/v1/ingest itself.

  NOTE: this is PLAIN HTTP. The server only speaks TLS if you pass
  both --cert and --key; no certificate is generated for you, and
  no certificate tooling ships in this bundle. Either keep this on
  an isolated/trusted segment, supply your own cert:
    lfa.cmd serve --host 0.0.0.0 --port 8443 --token <tok> \
                  --cert C:\path\cert.pem --key C:\path\key.pem
  or avoid the network entirely and use the USB tarball workflow.

WHAT IS IN THIS FOLDER
  runtime\   Embeddable CPython 3.13.7 (signed by the Python
             Software Foundation). Not registered with Windows; it does
             not touch the registry and does not affect any other Python.
  app\lfa\   The analyzer.
  app\site-packages\   PyYAML, Jinja2, MarkupSafe, tzdata.
  cases\     Default output directory for cases.
  SHA256SUMS Hash of every shipped file, for tool-integrity checks.

NOT INCLUDED
  'lfa.cmd remote' (live SSH acquisition) is unavailable in this build:
  it needs collector/collect.sh and an ssh client on the target network.
  Collect on the Linux host with collector/collect.sh and bring the
  resulting .tar.gz bundle here.

