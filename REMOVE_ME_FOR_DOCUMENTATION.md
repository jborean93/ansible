# Things to Document

+ The `ansible.module_utils.secrets` functions
+ New filter plugins for registering/masking secrets
+ What is a boundary, `display`, log files
+ `ansible-connection` `persistent_log_messages` option will leak secrets
+ Minimum secret length is 4
  + Secrets < 4 are ignored
  + Secrets from > 4 <= 6 will be masked by word boundary (SDFIX Add boundary chars here when implemented)
  + Secrets > 6 are masked wherever present
  + Secrets > 1024 are trimmed at 1024 and masked until this boundary
+ When loading a vaulted vars file, values are registered as secret
  + Keys are ignored
  + We will go into lists/dicts and register values recursively
+ Callback and `ANSIBLE_SUPPORTS_MASKING`
  + What is the attribute
  + When it is deprecated
  + How to properly masking secrets
