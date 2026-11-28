# Unix control group access design

The Unix control server creates a mode `0660` socket. The operating system checks the caller's access to the socket and its parent directories. Custom deployments arrange group ownership and directory traversal through their runtime layout.

Packaged Unix services use `pathchord:pathchord` ownership and mode `0750` for their runtime directory. Group members can connect and receive the local management privileges. They cannot replace the socket or its lock. Private state directories and control locks remain owner-only.
