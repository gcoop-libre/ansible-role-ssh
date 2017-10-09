SSH
===

Configure a host as an OpenSSH server and / or client.

If you choose to generate a Host Certificate, you should add the Certificate Authority Public Key to your `know_hosts` file, so the Host Key will be automatically accepted.

    @cert-authority *.example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxC+gikReZlWEnZhKkGzhcNeRD3dKh0L1opw4/LQJcUPfRj07E3ambJfKhX/+G4gfrKZ/ju0nanbq+XViNA4cpTIJq6xVk1uVvnQVOi09p4SIyqffahO9S+GxGj8apv7GkailNyYvoMYordMbIx8UVxtcTR5AeWZMAXJM6GdIyRkKxH0/Zm1r9tsVPraaMOsKc++8isjJilwiQAhxdWVqvojPmXWE6V1R4E0wNgiHOZ+Wc72nfHh0oivZC4/i3JuZVH7kIDb+ugbsL8zFfauDevuxWeJVWn8r8SduMUVTMCzlqZKlhWb4SNCfv4j7DolKZ+KcQLbAfwybVr3Jy5dSl Host Certificate Authority

Requirements
------------

The host which runs the Ansible role should have `OpenSSH >= 6.5`, because all the keys are generated locally and they are uploaded to the host.

Role Variables
--------------

Available variables are listed below, along with default values (see `defaults/main.yml`):

    ssh_ca_path: "{{ ssh_role_files }}"

Path where the Certificate Authority keys will be stored.

    ssh_server_moduli_path: "{{ ssh_role_files }}"

Path where the `moduli` and `moduli candidates` will be stored.

    ssh_keygen_keys_path: "{{ ssh_role_files }}/{{ inventory_hostname }}"

Path where the Host and User public and private keys will be stored. The Host and User certificates will be stored there too.

    ssh_keygen_iterations: 64

If the host has `OpenSSH >= 6.5` the private keys will be saved using the new format (`using -o flag`). This property specified the number of KDF (Key Derivation Function) rounds used for this.

    ssh_keygen_bits_rsa: 4096

Number of bits in the RSA keys that will be created. This value is used for Certificate Authority keys and also Host and User keys.

    ssh_keygen_bits_ecdsa: 384

Number of bits in the ECDSA keys that will be created when `ssh_server_host_key_ecdsa` is enabled.

    ssh_server_revoked_keys_path: "{{ ssh_role_files }}"

Path where the file with the `revoked keys` will be stored.

    ssh_client: False

This property enables the configuration of the host as an OpenSSH client.

    ssh_client_ipv6_enable: False

This property enables the use of IPv6 on the OpenSSH client.

    ssh_client_remote_hosts: []

List of hosts which connection will be affected by this configuration.

    ssh_client_ports:
      - 22

Default port of the outgoing connections.

    ssh_client_identities: []

Restrict the identity files that will be used for connections.

    ssh_client_cbc_required: False

Enables using `ciphers` with (`insecure`) CBC algorithms on the OpenSSH client.

    ssh_client_weak_hmac: False

Enables using `weak` hash algorithms on the OpenSSH client.

    ssh_client_weak_kex: False

Enables using `weak` key exchange algorithms on the OpenSSH client.

    ssh_client_password_login: False

Enables interactive login on the OpenSSH client.

    ssh_client_roaming: False

Enables experimental client roaming. This is known to cause potential issues with secrets being disclosed to malicious servers and defaults to being disabled.

    ssh_server: False

This property enables the configuration of the host as an OpenSSH server.

    ssh_server_regenerate_moduli: False

Enables the generation of the groups for the Diffie-Hellman Group Exchange (DH-GEX) protocol.

    ssh_server_regenerate_keys: False

Enables the generation and upload of a new pair of private and public host keys.

    ssh_server_regenerate_user_keys: False

Enables the generation of user keys.

    ssh_server_regenerate_revoked_keys: False

Enables the generation and upload of a revoked keys file.

    ssh_server_moduli_bits: 4096

The desired length of the primes of the groups for the Diffie-Hellman Group Exchange (DH-GEX) protocol.

    ssh_server_ca: ''

Filename of the Certificate Authority keys that will be used to sign host keys. You should leave it empty if you don't want to use host certificates.

    ssh_server_ca_passphrase: ''

Passphrase for the private key of the host Certificate Authority.

    ssh_server_certificate_validity: ''

Validity of the generated host Certificate.

    ssh_server_certificate_regenerate: False

Force the generation of a new certificate for the host.

    ssh_server_user_cas:
      ca_name:
        passphrase: '' (Default)
        path: '' (Default)
        file: ca_name (Default)

List of User Certificate Authorities which keys should be locally created and/or configured on the OpenSSH server to authenticate users using OpenSSH Certificates. The key of each dictionary is the name of the Certificate Authority and it may content the following properties:

`passphrase`: Passphrase for the private key of the user Certificate Authority.
`path`: Path where the keys should be stored when created.
`file`: Filename of the user Certificate Authority private key. The public key would be named as `file`.pub.

    ssh_server_user_certificate_regenerate: False

Force the generation of a new certificate for the user. This value could be overriden per user basis on the `ssh_server_user_keys` variable.

    ssh_server_user_certificate_agent_forwarding: False

Allow forwarding SSH Agent when establishing a connection with the user certificate. This value could be overriden per user basis on the `ssh_server_user_keys` variable.

    ssh_server_user_certificate_port_forwarding: False

Allow port forwarding when establishing a connection with the user certificate. This value could be overriden per user basis on the `ssh_server_user_keys` variable.

    ssh_server_user_certificate_pty: True

Allow PTY allocation when establishing a connection with the user certificate. This value could be overriden per user basis on the `ssh_server_user_keys` variable.

    ssh_server_user_certificate_user_rc: False

Allow execution of ~/.ssh/rc by sshd when establishing a connection with the user certificate. This value could be overriden per user basis on the `ssh_server_user_keys` variable.

    ssh_server_user_certificate_x11_forwarding: False

Allow X11 forwarding when establishing a connection with the user certificate. This value could be overriden per user basis on the `ssh_server_user_keys` variable.

    ssh_server_user_certificate_validity: ''

Validity of the generated user Certificate. This value could be overriden per user basis on the `ssh_server_user_keys` variable.

    ssh_server_user_keys:
      - user: username
        passphrase: h4rdPa55phras3
        certificate_authority: ca_name
        certificate_regenerate: "{{ ssh_server_user_certificate_regenerate }}"
        certificate_command: 'echo No login'
        certificate_sources:
          - 192.168.1.10
        certificate_options:
          agent-forwarding: "{{ ssh_server_user_certificate_agent_forwarding }}"
          port-forwarding: "{{ ssh_server_user_certificate_port_forwarding }}"
          pty: "{{ ssh_server_user_certificate_pty }}"
          user-rc: "{{ ssh_server_user_certificate_user_rc }}"
          x11-forwarding: "{{ ssh_server_user_certificate_x11_forwarding }}"
        certificate_validity: "{{ ssh_server_user_certificate_validity }}"
        file: username

List of users which keys will be created by the rol. Each dictionary of the list has the following properties:

* `user` indicates the username which keys will be created.
* If the `passphrase` property is used, the value will be user as passphrase for the private key.
* `certificate_authority` indicates which User Certificate Authority should be used to sign the certificate.
* `certificate_regenerate` allows you to override the value of `ssh_server_user_certificate_regenerate`.
* `certificate_command` force the execution of the specified command.
* `certificate_sources` restrict the source addresses from which the certificate could be used.
* `certificate_options` allows you to override the different restrictions when establishing a connection with the certificate.
* `certificate_validity` allows you to override the value of `ssh_server_user_certificate_validity`.
* `file`: indicates the filename for the keys. If this property is not used or it's empty, the `user` property will be used.

    ssh_server_revoked_keys: []

List of user public keys to be revoked to access the host.

    ssh_server_revoked_sha1: []

List of SHA1 hashed of the user keys to be revoked to access the host.

    ssh_server_revoked_certificates:
      ca_name: []

Certificates to be revoked to access the host. The property should be a dictionary with the User Certificate Authority name as key and a list of certificate's IDs signed with that Certificate Authority as value.

    ssh_server_revoked_serials:
      ca_name: []

Certificates to be revoked to access the host. The property should be a dictionary with the User Certificate Authority name as key and a list of certificate's serial numbers signed with that Certificate Authority as value.

    ssh_server_root_key_login: False

Specifies if the root user can access the host using a public key, or his access will be always denied.

    ssh_server_ports:
      - 22

List of ports on which the OpenSSH server should listen.

    ssh_server_ipv6_enable: False

This property enables the use of IPv6 on the OpenSSH server.

    ssh_server_listen_to:
      - 0.0.0.0

List of local addresses on which the OpenSSH server should listen.

    ssh_server_host_key_rsa: True

The OpenSSH server will use RSA host keys.

    ssh_server_host_key_dsa: False

The OpenSSH server will use DSA host keys.

    ssh_server_host_key_ecdsa: True

The OpenSSH server will use ECDSA host keys.

    ssh_server_host_key_ed25519: False

The OpenSSH server will use ED25519 host keys.

    ssh_server_cbc_required: False

Enables using `ciphers` with (`insecure`) CBC algorithms on the OpenSSH server.

    ssh_server_weak_hmac: False

Enables using `weak` hash algorithms on the OpenSSH server.

    ssh_server_weak_kex: False

Enables using `weak` key exchange algorithms on the OpenSSH server.

    ssh_server_max_auth_retries: 2

Maximum number of authentication attempts permitted per connection.

    ssh_server_use_pam: False

Enables PAM interface for authentication.

    ssh_server_deny_users: []

List of users which access will be denied.

    ssh_server_allow_users: []

List of users which access will be allowed.

    ssh_server_deny_groups: []

List of groups which access will be denied.

    ssh_server_allow_groups: []

List of groups which access will be allowed.

    ssh_server_client_alive_interval: 600

Timeout interval in seconds after which if no data has been received from the client, the OpenSSH server will send a message through the encrypted channel to request a response from the client.

    ssh_server_client_alive_count: 3

Number of client alive messages which may be sent without the OpenSSH server receiving any messages back from the client. If this threshold is reached while client alive messages are being sent, the OpenSSH server will disconnect the client, terminating the session.

    ssh_server_tcp_forwarding: False

Specifies whether TCP forwarding is permitted.

    ssh_server_agent_forwarding: False

Specifies whether ssh-agent forwarding is permitted.

    ssh_server_motd: False

Specifies whether the OpenSSH server should print /etc/motd when a user logs in interactively.

    ssh_server_last_log: False

Specifies whether the OpenSSH server should print the date and time of the last user login when a user logs in interactively.

    ssh_server_banner: ''

Banner to send to the remote user before authentication is allowed.

    ssh_server_debian_banner: False

Specifies whether the distribution-specified extra version suffix is included during initial protocol handshake.

    ssh_server_sftp: False

Enabled the `sftp` subsystem.

    ssh_server_sftp_chroot_dir: /home/%u

Specifies the pathname of a directory to chroot to after authentication the users which belongs to the `sftponly`.

Dependencies
------------

None.

Example Playbook
----------------

    - hosts: servers
      vars_files:
        - vars/main.yml
      roles:
         - gcoop-libre.ssh

*Inside `vars/main.yml`*:

    ssh_server: True

License
-------

GPLv2

Author Information
------------------

This role was created in 2017 by [gcoop Cooperativa de Software Libre](https://www.gcoop.coop).
