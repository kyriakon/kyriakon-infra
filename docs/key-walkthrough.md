# Making a key

Your account has two keys, and they do different jobs.

The mail key is how you read your mail. Your messages are PGP ciphertext on our server, encrypted to its public half when they arrive, so the private half never leaves the machine that made it. Without it your mailbox cannot be opened.

The upload key is how you publish a website and use your git repositories. Both are reached by ssh with a key, and neither accepts a password. This key is a step for anyone who wants a website, not an extra: a member who skips it gets mail and nothing else.

Make both keys on your own machine. Make the mail key in Thunderbird's OpenPGP Key Manager on a desktop, or with gpg at a terminal. Make the upload key with `ssh-keygen -t ed25519` at a terminal. This site only ever receives the public half.

## The recovery phrase

Your recovery phrase is a passphrase-protected offline export of your mail private key. Make it as soon as the key exists. In Thunderbird you make it with the Key Manager's secret-key export; with gpg you make it with `gpg --armor --export-secret-keys`. Keep the export on a drive that stays away from the laptop, and keep the passphrase apart from it. The export and the passphrase together are the only way back into the mailbox on a new machine.

Do not send the recovery phrase to yourself by email, and do not store it in a password manager that lives on the same machine as the private key.

The platform holds no key that opens your mailbox. Zero-access covers message content and not the addressing information mail needs to move: sender, recipient, timestamp and size appear in the server's logs and in the outer message wrapper, and the seven-day window bounds how long the raw record exists. If you lose the private key and the recovery phrase, the mail is gone permanently. We cannot restore it, because no key exists here to open it.

## Thunderbird on a desktop

Thunderbird on a desktop is the primary path. It has OpenPGP built in, so you do not need a separate program.

1. Install Thunderbird and open the OpenPGP Key Manager, under Tools.
2. Choose to generate a new key pair, with the address you applied for as its identity, and no name. A name or another address in the key is published with `keys/<username>.asc`, so leave the identity as the address alone; if you do add one, the reviewer sees it in the review email before approval.
3. Choose a passphrase, and keep it somewhere safe, apart from the machine.
4. Choose "Key does not expire". A mail key must not expire: delivery stops on its expiry date, without a word, so there is no date to renew.
5. Export the public key to a file. This is the half you paste into the application.
6. Export the secret key from the Key Manager. The passphrase-protected export it writes is your recovery phrase, so keep it apart from the machine.

When the account is approved, the mail address starts accepting mail. Mail that arrives before your client is set up waits on the server, encrypted, and becomes readable once the key is in place.

Thunderbird for Android is not covered by this page. The prototype has not tested it end to end, so describing it here would be a claim we cannot stand behind. Use the desktop path until that changes.

## A key at a terminal

`gpg` at a terminal makes the same mail key, with no mail client installed.

1. Run `gpg --default-preference-list 'AES256 AES192 AES128 SHA512 SHA384 SHA256 ZLIB BZip2 ZIP Uncompressed' --full-generate-key`. The list leaves AEAD out: gpg 2.5 adds AEAD by default, and the application refuses a key that advertises it, because some mail clients cannot open AEAD mail.
2. Choose "RSA and RSA" and 4096 bits. Choose an expiry of 0, which means the key never expires.
3. Leave Real name and Comment empty, and put the address you applied for in Email address. gpg accepts an empty name, and a name or another address in the key is published with `keys/<username>.asc`.
4. Choose a passphrase, and keep it somewhere safe, apart from the machine.
5. Export the public key as text, replacing the address with the one you applied for: `gpg --armor --export you@kyriakon.net > mail-public.asc`. Paste that file into the application.
6. Export the private key as your recovery phrase, and keep it apart from the machine: `gpg --armor --export-secret-keys you@kyriakon.net > mail-secret.asc`.

## The upload key

An upload key is an Ed25519 key pair. It is separate from the mail key, and its private file is the only copy.

1. Run `ssh-keygen -t ed25519`. It asks where to save the key, and it offers a passphrase. A passphrase is optional; without one, any file copied to the machine can use the key.
2. Keep the private file on the machine you will upload from.
3. Print the public half, which starts `ssh-ed25519`, with `cat ~/.ssh/id_ed25519.pub`, and give it to the application.

The two ports are these, and they are the only two you need:

- sftp on port 22, for uploading your website;
- git on port 2222, for your `pass` repositories.

There is no interactive shell on the account. The sftp session is confined to your own website directory, and the git session can only reach the repositories you own. If a client asks for a shell, that is a client setting to change, not a missing permission to request.

## Where the key goes

Paste the mail public key when the application asks for it. If your client refuses the paste because the address line is too long, mail the key to apply@kyriakon.net with your application's token as the subject, and name the mailbox in the message.

Paste the upload public key on the upload key page. It is optional in the form and not optional in practice: without it you get mail and nothing else.
