SSH
===

Configure a host as an OpenSSH server and / or client.

If you choose to generate a Host Certificate, you should add the Certificate Authority Public Key to your `known_hosts` file, so the Host Key will be automatically accepted.

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

Path where the Host public and private keys will be stored. The Host certificates will be stored there too.

    ssh_keygen_user_keys_path: "{{ ssh_role_files }}"

Path where the User public and private keys will be stored. The User certificates will be stored there too.

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

    ssh_client_cbc_required: False

Enables using `ciphers` with (`insecure`) CBC algorithms on the OpenSSH client.

    ssh_client_weak_hmac: False

Enables using `weak` hash algorithms on the OpenSSH client.

    ssh_client_weak_kex: False

Enables using `weak` key exchange algorithms on the OpenSSH client.

    ssh_client_password_login: False

Enables interactive login on the OpenSSH client.

    ssh_client_control_master: auto

Enables the sharing of multiple sessions over a single network connection. Valid values are: `yes`, `no`, `ask`, `auto`, `autoask`.

    ssh_client_control_path: "~/.ssh/.master-%r@%h:%p"

Specify the path to the control socket used for connection sharing. An empty string will disable connection sharing.

    ssh_client_escape_char: '~'

Sets the escape character. The value should be a single character or `none` to disable the escape character entirely (making the connection transparent for binary data).

    ssh_client_visual_host_key: True

If this property is set to `True`, an ASCII art representation of the remote host key fingerprint is printed in addition to the fingerprint string at login and for unknown host keys.

    ssh_client_roaming: False

Enables experimental client roaming. This is known to cause potential issues with secrets being disclosed to malicious servers and defaults to being disabled.

    ssh_client_extra_configs:
      LogLevel: FATAL

Dictionary of OpenSSH configurations that does not have a property on this role. The OpenSSH option name should be used as key of the item and the desired value as its value.

    ssh_client_remote_hosts:
      - name: hostname
        hostname: 192.168.10.10
        port: 22
        host_key_alias: hostname.example.com
        strict_host_key: True
        user: debian
        forward_agent: False
        identity_file: id_rsa
        certificate_file: id_rsa-cert.pub
        local_forwards:
          - local_port: 1234
            local_address: ''
            remote_port: 80
            remote_address: 127.0.0.1
        remote_forwards:
          - remote_port: 1234
            remote_address: ''
            local_port: 80
            local_address: 127.0.0.1
        dynamic_forwards:
          - local_port: 1234
            local_address: ''
        extra_configs:
          LogLevel: FATAL
        aliases:
          - web.example.com
          - www.example.com

List of connections to remote OpenSSH servers that should be available on the global OpenSSH configuration. Each dictionary of the list has the following properties:

* `name`: Identifies the host or hosts whose connections will be configured. A single ‘\*’ as a pattern can be used to provide global defaults for all hosts.  The host is usually the hostname argument given on the command line. A pattern entry may be negated by prefixing it with an exclamation mark (‘!’).  If a negated entry is matched, then the Host entry is ignored, regardless of whether any other patterns on the line match.  Negated matches are therefore useful to provide exceptions for wildcard matches.
* `hostname`: Specifies the real host name to log into. This can be used to specify nicknames or abbreviations for hosts. Arguments to HostName accept the tokens described in the TOKENS section of `ssh_config manpage`. Numeric IP addresses are also permitted (both on the command line and in HostName specifications). The default is the name given on the command line.
* `port`: Specifies the port number to connect on the remote host. The default is 22.
* `host_key_alias`: Specifies an alias that should be used instead of the real host name when looking up or saving the host key in the host key database files. This option is useful for tunneling SSH connections or for multiple servers running on a single host.
* `strict_host_key`: If this property is set to `True`, ssh will never automatically add host keys to the `~/.ssh/known_hosts` file, and refuses to connect to hosts whose host key has changed. This provides maximum protection against trojan horse attacks, though it can be annoying when the `/etc/ssh/ssh_known_hosts` file is poorly maintained or when connections to new hosts are frequently made. This option forces the user to manually add all new hosts. If this property is set to `False`, ssh will automatically add new host keys to the user known hosts files.
* `user`: Specifies the user to log in as. This can be useful when a different user name is used on different machines. This saves the trouble of having to remember to give the user name on the command line.
* `forward_agent`: Specifies whether the connection to the authentication agent (if any) will be forwarded to the remote machine. The property must be `True` or `False` (the default). Agent forwarding should be enabled with caution. Users with the ability to bypass file permissions on the remote host (for the agent's Unix-domain socket) can access the local agent through the forwarded connection. An attacker cannot obtain key material from the agent, however they can perform operations on the keys that enable them to authenticate using the identities loaded into the agent.
* `identity_file`: Specifies a file from which the user's DSA, ECDSA, Ed25519 or RSA authentication identity is read. It should be located in the users `~/.ssh` directory. If no certificates have been explicitly specified by `certificate_file`, ssh will try to load certificate information from the filename obtained by appending -cert.pub to the path of a specified IdentityFile. IdentityFile may also be used in conjunction with CertificateFile in order to provide any certificate also needed for authentication with the identity.
* `certificate_file`: Specifies a file from which the user's certificate is read. It should be located in the users `~/.ssh` directory. A corresponding private key must be provided separately in order to use this certificate either from an `identity_file` property or -i flag to ssh, via ssh-agent, or via a PKCS11Provider.
* `local_forwards`: Specifies that a TCP port on the local machine be forwarded over the secure channel to the specified host and port from the remote machine. IPv6 addresses can be specified by enclosing addresses in square brackets. Multiple forwardings may be specified as different items of this list, and additional forwardings can be given on the command line. `local_port` indicates the local port to use. Only the superuser can forward privileged ports. An explicit `local_address` may be used to bind the connection to a specific address. The `local_address` of localhost indicates that the listening port be bound for local use only, while an empty address or ‘\*’ indicates that the port should be available from all interfaces. `remote_port` indicates the remote port to use as the other end of the tunnel and `remote_address` allows to override `127.0.0.1` as the remote IP address.
* `remote_forwards`: Specifies that the `remote_port` TCP port on the remote machine be forwarded over the secure channel to the specified `local_address` host and `local_port` port from the local machine. IPv6 addresses can be specified by enclosing addresses in square brackets. Multiple forwardings may be specified as different items of this list, and additional forwardings can be given on the command line. Privileged ports can be forwarded only when logging in as root on the remote machine. If the `remote_address` is not specified or it is ‘\*’, then the forwarding is requested to listen on all interfaces.
* `dynamic_forwards`: Specifies that a `local_port` TCP port on the local machine be forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine. IPv6 addresses can be specified by enclosing addresses in square brackets. An explicit `local_address` may be used to bind the connection to a specific address. The `local_address` of localhost indicates that the listening port be bound for local use only, while an empty address or ‘\*’ indicates that the port should be available from all interfaces. Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS server. Multiple forwardings may be specified as different items of this list, and additional forwardings can be given on the command line. Only the superuser can forward privileged ports.
* `extra_configs`: Dictionary of OpenSSH configurations that does not have a property on this role. The OpenSSH option name should be used as key of the item and the desired value as its value.
* `aliases`: List of aliases for the connection. The role will create new `Host` entries using this aliases and the configurations of the other properties of the list item.

    ssh_client_known_hosts:
      - hostnames:
          - host.example.com
          - *.pattern
          - hostname-hash
        cert_authority: False
        revoked: False
        keytype: ssh-rsa
        key: AAAAB3NzaC1yc2EAAAADAQABAAABAQDrGDvCxePm839ib0zKw5IXPZbFpK9mGa3C+PddxCjDREwqJXN0yCmB+cmyMrHveVoQcFBg/jCXCqVdkT1GuFCGAvBh2Ejvs2NyGX089m1Crk+f1b1E6b9jMFD3WVZrY0PLCjbbo5MBVLBj5WWthxUvAaeC7wrwqK2bOQi6KZroHNNCagEKEDCpDXLMWGO5TOCPXzHGoqMAcnyZ+9E1bqnKfVU+FhtxYWJq/M6fkXXDzM8AEbLd1D3YHYVu45dkbbrMyL940a1uadnbNS1hqz8OGsnejvoJLeUhI4EeJg88KIp5Owq37SV5VqBTkVTRN5fJl4Bz2dvCLffddWPK8psd
        comment: ''

List of host keys that should be added to the global known hosts file (`/etc/ssh/ssh_known_hosts`). The available properties of each list item are:

* `hostnames`: List of hostnames that will match against the key. Each item can be a complete hostname or IP, a regular expression to match against the `Hostname` or `HostKeyAlias` or a hash of the hostname.
* `cert_authority`: Indicates that the key is the public key of a Certificate Authority used to sign the host keys.
* `revoked`: Indicate that the key is revoked and must not ever be accepted.
* `keytype`: Type of the SSH key. It can be obtained directly from the public host or Certificate Authority key.
* `key`: Public key of the host or Certificate Authority. It can be obtained directly from the public host or Certificate Authority key.
* `comment`: Comment for the key.

There is more information about the known hosts file on the [SSHd manpage](https://man.openbsd.org/sshd.8#SSH_KNOWN_HOSTS_FILE_FORMAT).

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
        certificate_id: username-{{ ansible_date_time.date }}
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
* `certificate_id` indicates the ID of the certificate. The default value will be generated by the `user` and the current date in ISO format.
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
