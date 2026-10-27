# Making a key

Your account has two keys, and they do different jobs.

The mail key is how you read your mail. Your messages are PGP ciphertext on our server, encrypted to its public half when they arrive, so the private half never leaves the machine that made it. Without it your mailbox cannot be opened.

The upload key is how you publish a website and use your git repositories. Both are reached by ssh with a key, and neither accepts a password. This key is a step for anyone who wants a website, not an extra: a member who skips it gets mail and nothing else.

You can make both in a browser at the generator, or make the mail key in Thunderbird on a desktop. The recovery phrase is the part that matters most, so read that section before you start.

## The recovery phrase

When a key is made, a recovery phrase is shown. It is the only way to unlock the private key on a new machine if the key file is lost, and it is the password you will be asked for when your mail client first uses the key.

Write it down on paper. Write it down again and keep the two copies in separate places, because one copy in the same bag as the laptop is one copy. Do not keep it in a password manager that lives on the same machine as the key file, and do not send it to yourself by email.

The platform holds no key that opens your mailbox. Zero-access covers message content and not the addressing information mail needs to move: sender, recipient, timestamp and size appear in the server's logs and in the outer message wrapper, and the seven-day window bounds how long the raw record exists. If you lose the device and the recovery phrase, the mail is gone permanently. We cannot restore it, because no key exists here to open it.

## Thunderbird on a desktop

Thunderbird on a desktop is the primary path. It has OpenPGP built in, so you do not need a separate program.

1. Install Thunderbird and open the OpenPGP Key Manager, under Tools.
2. Choose to generate a new key pair, with the address you applied for as its identity.
3. Choose a passphrase, and write it down with the recovery phrase.
4. Set no expiry date, or a date far enough away that you will remember to renew it.
5. Export the public key to a file. This is the half you paste into the application.
6. Keep the private key in Thunderbird's own key store, and keep the recovery phrase somewhere else.

When the account is approved, the mail address starts accepting mail. Mail that arrives before your client is set up waits on the server, encrypted, and becomes readable once the key is in place.

Thunderbird for Android is not covered by this page. The prototype has not tested it end to end, so describing it here would be a claim we cannot stand behind. Use the desktop path, or the browser generator on a desktop, until that changes.

## The browser generator

The generator is at https://signup.kyriakon.net/ and runs in your browser. The page's own code makes the key on your machine. Nothing is uploaded while it runs, and the private key file is written by the page for you to keep.

It makes the mail key and the upload key together, and it shows the recovery phrase once. Write the phrase down before you close the tab.

Use it if you would rather not install a mail client first, or if the machine you are applying from has no terminal. It is also the path for the upload key, since making an ssh key without a terminal is otherwise awkward.

## The upload key

An upload key is an Ed25519 key pair. It is separate from the mail key, and its private file is the only copy.

1. Make the key in the browser generator, or with `ssh-keygen -t ed25519` if you have a terminal.
2. Keep the private file on the machine you will upload from.
3. Give the public half, which starts `ssh-ed25519`, to the application.

The two ports are these, and they are the only two you need:

- sftp on port 22, for uploading your website;
- git on port 2222, for your `pass` repositories.

There is no interactive shell on the account. The sftp session is confined to your own website directory, and the git session can only reach the repositories you own. If a client asks for a shell, that is a client setting to change, not a missing permission to request.

## Checking a key

The same site has a key check page. Paste a public key and it reports whether a client could use it: whether a subkey can encrypt, whether the key advertises a packet your mail client cannot read, and whether it has expired or been revoked.

The check runs in the browser and uploads nothing. A warning is not a refusal. The platform records the verdict with your application and lets a person read it, because it cannot verify what any client generated and a refusal would send a working setup to a support queue.

## Where the key goes

Paste the mail public key when the application asks for it. If your client refuses the paste because the address line is too long, mail the key to apply@kyriakon.net with your application's token as the subject, and name the mailbox in the message.

Paste the upload public key on the upload key page. It is optional in the form and not optional in practice: without it you get mail and nothing else.
