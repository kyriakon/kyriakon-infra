# Signup copy, section by section

Working notes for the signup prototype. Each section of member-facing copy has two or
three options and a recommendation. Pick one per section and the mock is rebuilt from
the picks.

Picks are recorded under "Settled so far" at the end of this file, and the recommended
option stands wherever nothing is recorded there.

Three things run through all of it. The tone is plain and unhurried, which suits a small
platform whose operator you can write to. Nothing promises more than it does. Every limit
appears where the promise is made, not in a policy nobody opens.

Placeholders in the copy: the example member is `theophilus`, the outside address is
`someone@example.invalid`, and prices, dates and counts are the ones in the mock.

## 1. Splash: the heading

It has to say what this is, and who it is for, in one line.

- A. Mail, a website and git repositories, for Orthodox Christians and their parishes.
- B. A home on the internet for Orthodox parishes and people.
- C. Secure email, a website, and git repositories, run by Orthodox Christians.

A lists what you get and reads like a specification. B is warmer and says what it is for,
at the cost of not saying what it is. C is the splash as it stands today, so it keeps one
voice with the capsule mirror.

Recommended: A. People arrive knowing what mail and a website are, and the list is what
they came to check.

- Secure Encrypted Email and Hosting, run by Orthodox Christians.

## 2. Splash: what you get, and the limits

Three short blocks, each heading followed by two or three sentences.

Heading options for the mail block:

- A. Mail you can read and we cannot.
- B. Your mail, sealed with your key.
- C. Private mail.
- D. Secure encrypted email. (chosen)

A is the plainest and leads with the property that matters. B is gentler and less
specific. C is a claim anyone can make. D is the phrase a reader already recognises, which
matters more for this audience than being distinctive, and it works because the paragraph
under it carries the fact that makes this platform different: that we hold ciphertext and
no key. The heading may stay familiar as long as the sentence under it is exact.

Body options for the mail block:

- A. Your mail is encrypted to your own key the moment it arrives. The server holds
  ciphertext and no key, so we cannot read your messages, and no request or fault on our
  side changes that. The cost is that if you lose your key and your recovery phrase, the
  mail is gone. Nobody here can restore it.
- B. Everything sent to you is encrypted before it is stored, using a key that exists
  only on your own computer. We hold the sealed envelope and no way to open it. If you
  lose the key and the words that unlock it, the mail cannot be recovered by anyone, us
  included.

A states the property and then the cost in the same breath. B uses the envelope image,
which some readers find easier and some find childish for a security claim.

Recommended: A, and the sentence about the cost stays in the same paragraph. Splitting it
into a footnote is how a platform ends up promising something it cannot deliver.

## 3. Splash: the price, and who is not charged

- A. £20 a year. Clergy, monastics and anyone who cannot afford it are not charged.
- B. £20 a year, or nothing at all if you are clergy, a monastic, or simply unable to pay.
  Say so on the form and that is the end of it.
- C. £20 a year. Nobody is turned away for want of money.

A is short and states the tiers. B says how it works, which is what people want to know
before asking. C is warm and vaguer, and it leaves the reader unsure whether they
qualify.

Recommended: B. The thing that stops people asking is not knowing whether the offer
applies to them, so the copy should say who decides and how.

Both are settled in principle. The price line stays as B, and a parish wanting its own
domain or several addresses is invited to write to us rather than quoted a price. What is
still open is the tier set itself, because the £50/yr in the proposal looks high for a
rural parish beside providers that sell a domain with several addresses for less, and
because nobody has established what an organisation account costs to run here. Both
questions are out to research in tickets [#189](https://github.com/kyriakon/kyriakon-infra/issues/189)
and [#190](https://github.com/kyriakon/kyriakon-infra/issues/190), and the decision that
waits on them is [#188](https://github.com/kyriakon/kyriakon-infra/issues/188). No price
for the parish tier appears on the site until then.

- £20 a year. Free for clergy, monastics, and those who are unable to pay. Please let us know on the form!

## 4. Key check: heading and first line

- A. Does your key work here? Paste your public key. Nothing leaves your
  browser.
- B. Will your mail work with us? Paste your public key and find out. Nothing leaves your
  browser.
- C. Check your key before you apply.

A asks the question the reader has and then answers where the checking happens. B is
warmer and slightly vaguer about what is being checked. C is a heading with nothing under
it.

Recommended: A, with B's phrase "nothing leaves your browser" if you want the privacy
point stated more gently than "nothing is sent to us".

- Does your key work here? Paste your public key to check. Nothing leaves your
  browser.

## 5. Key check: the three answers

The success line.

- A. This key will work. It has an encryption subkey, it asks for no AEAD cipher, and it
  is not expired.
- B. This key is fine. It can receive encrypted mail and your mail program will be able
  to open what we send.

A names the three things checked, which teaches the reader what matters. B is friendlier
and tells them nothing they could act on later.

B

The failure lines, which are the ones that matter, because a member who reads one has a
problem to fix.

- A. Your mail would be unreadable. This key asks for an AEAD cipher, and some mail
  programs cannot open a message encrypted that way. Ask your mail program to remove AEAD
  from the key's preferences, or make a new key with the generator on the application
  page.
- B. There is no encryption subkey. This key can sign documents but cannot be written to,
  so mail addressed to you would be refused at our end rather than delivered. Make a key
  with an encryption subkey.

Recommended: keep A's shape, which names what is wrong, what it would do, and what to do
about it. A warning that does not say what to do is a support ticket.

A 

## 6. Application: the opening line

- A. A person reads every application. Nothing is charged until it is approved.
- B. Take your time. Everything here goes to one person, and nothing is charged until we
  have read it.
- C. Apply for an account.

A sets the two expectations that matter, that a human decides and that nothing is charged
yet. B is warmer and puts the human first. C leaves both facts to be discovered.

Recommended: A, or B if you want the page to open gently. Either way the two facts have to
be there.

B

## 7. Application: the username

Label and help text.

- A. Username. This becomes your address, theophilus@kyriakon.net, and your site,
  theophilus.kyriakon.net.
- B. The name you want. It becomes both your mail address and your website address.
  Lowercase letters, digits and hyphens, up to 31 characters.
- C. Your name here. Checked as you type.

Recommended: B. It explains the consequence before the reader commits, and states the
rules in the same place. The example address in A is worth keeping underneath, since
seeing the finished address is what makes it click.

B with the example address under it.

## 8. Application: the address outside the platform

The label, then the consequence of leaving it empty. The label has to be clear enough
that nobody thinks we are asking for their main address.

- A. An address outside this platform (optional).
- B. Another address, in case we cannot reach you here (optional). Can be added or removed
  at any time.
- C. Your other email address (optional). Used only for notices.

Recommended: B. "Outside this platform" is precise and slightly cold, and "your other
email" invites exactly the privacy question the field is meant to leave open.
B

The consequence, which has to be stated in full and without drama.

- A. If you leave it empty, we can only reach you inside this account. If you lose your
  key or your mail program, we will not be able to reach you. An unpaid account will be
  deleted after some time along with its mail.
- B. We would rather have a way to reach you, and we understand why you might not want to
  give one. Without it, everything still works until something goes wrong, and then we
  have no way to tell you.

Recommended: A. It is the version that says what happens rather than how we feel about it,
and the reader can weigh it.

A 

Worth a sentence either way, and it belongs here rather than in the privacy notice: it is
used for notices only, never shared, and never used to look you up anywhere else.

## 9. Application: the mail password

- A. Mail password. You will type this into your mail program, not here.
- B. Account password. Choose something you can type on a phone. You can change it later from
  your account page.

Recommended: B. The first thing people do with a password field is worry about which
password to use, and both facts answer the worry.

B

## 10. Keys: the mail key and the recovery phrase

The step heading.

- A. Make your mail key.
- B. First, your mail key.
- C. Your mail key.

Recommended: A. It is a thing the reader does, not a thing they have.
A

The recovery phrase, which is the most important paragraph in the whole flow.

- A. Write these eight words on paper, now. Anyone who has both the words and the key file
  can read your mail. We do not have either of them, which is why we cannot read it, and why we cannot recover it for you.
- B. Write these eight words down and keep them away from the file. If you lose both, your
  mail is gone. There is no reset, no security question, and no way for us to help.
- C. These words are the only way back in if you lose the file. Somewhere separate, and
  somewhere you will still have it in five years.

A explains who this protects against, which is what makes someone take it seriously. B is
blunter and leads with loss. C is quiet and treats it as obvious, which is how people come
to skip it.

A

Recommended: A. It says who can read the mail and why we cannot help, which is the
sentence that makes people write the words down.

## 11. Keys: the upload key

- A. Your upload key. This is what lets you put a website up and push to your
  repositories. It is not the mail key and it does not unlock anything you have written.
  Keep the private file safe, because it is the only copy.
- B. Your upload key. Needed only if you want a website or repositories. We never see the
  private half.

  A

Recommended: A. The confusion between the two keys is the thing to prevent, so naming the
difference is worth the extra sentence.

## 12. Keys: putting the key into a mail program

- A. Put the key into your mail program. Follow the walkthrough for Thunderbird, on a computer or a phone.

- B. Setting up. Follow the walkthrough for Thunderbird, on a computer or a phone.

A

Recommended: A. The promise of pictures is what stops someone deciding this is beyond
them, and it has to be true when the page ships.

The first mail, which belongs here as well as later:

- A. When your account opens we send you one message, encrypted. If you can read it,
  everything works. If you cannot, nothing is lost, and the walkthrough has a section for
  exactly that.
- B. The first message you receive is a test. If you can read it, you are done.

Recommended: A. "Nothing is lost" is the sentence that stops someone giving up at the
first failure.

A

## 13. Application: the questions about you

The opening line, which decides whether people answer.

- A. All of this is optional. It goes to one person, it is not published, and it is
  deleted with your application. These answers will make it easier and quicker for us to approve you.
- B. These are the questions we would ask if you came to the door. None of them are
  required but they make approval quicker and more likely. Plese
- C. Tell us about yourself (optional).


A 


A states plainly what happens to the answers. B is warmer and explains why the questions
are being asked at all, which is the honest answer to "why does a hosting company want to
know my diocese".

Recommended: B, with A's sentence about deletion. The reader is being asked something
personal and is owed both the reason and the handling.

The blessing question, for monastics, which is the one required answer.

- A. If you are a monastic, do you have your elder's or confessor's blessing to have an account?
- B. For monastics: has your elder blessed you to keep an account here? If he has, a line
  from him is enough.
- C. If you are a monk or a nun, the blessing of your elder is required.


A 

Recommended: A, and B's second sentence if you want it to be easy to comply. C states a
requirement without saying how to satisfy it.

## 14. Application: the acceptance checkbox

- A. I accept the terms, the acceptable use policy and the privacy notice.
- B. I have read and accept the terms, the acceptable use policy and the privacy notice.
  (versions listed with dates)
B
Recommended: B. "I have read" is the wording that survives a dispute, and the version
identifiers belong next to it rather than in the email alone.

## 15. Application received

- A. Thank you. That is with us.
- B. Received. A person will read it.
- C. That is with us. Nothing more is needed from you today.

Received, thank you for your application! A person will review it and get back to you.


Recommended: B, or C if the page also has to tell them about the status link. Naming the
human is the reassurance people are looking for after typing something personal into a
form.

The status link line:

- A. Save this link or write it down. It will show your application's status and it is how
  we tell you the outcome if you gave no other address.
- B. Anyone with this link can see your application. Keep it as you would a password.

Recommended: both, A first and B after it. The second sentence is the one that makes
someone treat it carefully, and leaving it out is how a link ends up pasted into a group
chat.

Both.

## 16. Status link

Heading.

- A. Where your application has got to.
- B. Your application.
- C. Application status.

Recommended: A. The others read like a database field.

C

The approved state, which is also the payment step:

- A. Approved. Your account is open at: theophilus@kyriakon.net, with mail working and your
  site answering on HTTP until its certificate arrives. The final step remaining is payment.
- B. You are approved. Your address already works. One thing remains.

Recommended: A, because it tells them the certificate is coming rather than leaving them
to notice the missing padlock and worry.

The declined state:

- A. We were not able to open an account, and we will look again if you ask us to.
- B. Not approved this time. You are welcome to write to us about it.

 <!-- I am are very sorry but we have decided to decline your application at this time. Please write to us if you have any further information that may help us to reconsider. ! !!!! (give in input on this please)
Recommended: A. "This time" and "you are welcome" are the parts that keep it courteous.

 -->
Perhapse its better to use the same text as the decline email.

## 17. Approval email

This one is yours rather than a member's, so the choices are about what you want in front
of you at the moment of deciding.

- A. Everything in one message, with three buttons at the end. The applicant's own words
  are in the body above them.
- B. A short message with the facts you decide on, and their words one command away.

You chose A already, so the only question left is the subject line.

- A. Application: theophilus
- B. theophilus has applied


A 
Recommended: A. It sorts and searches better in a mailbox you will come back to.

## 18. Decline

- A. We are not able to open an account for you at the moment. If you think we have this
  wrong, reply to this message. A word from your priest, or from someone we already know,
  usually settles it, and we are glad to look again. We will hold the application for a
  week, and after that it is deleted and the name is free for anyone to take.
- B. We are not able to open an account for you just now. If we have this wrong, write to
  us. We will keep the application for a week.

Recommended: A. For a community this size the vouch is a real path back in, and naming it
is what makes the decline feel like a door rather than a wall.

A

The monastic decline, which is the one case where the message says what is missing.

- A. We have not been able to reach your elder. If you can ask him to write to us, or send
  us his blessing, we will look again.
- B. The blessing of your elder is what we are waiting for.

Recommended: A. It says what would fix it and leaves the initiative with the applicant.

!!? Are we writing to the elder?? 


## 19. Payment: card

The acknowledgement, which has legal weight and has to be readable anyway.

- A. I ask you to begin supplying the service immediately, and I understand that this is
  digital content supplied at once.
- B. Please start my account now. I understand that this is digital content, supplied
  immediately.

Recommended: A for the text recorded against the account, B for the checkbox if you want
the reader to feel they are asking for something rather than accepting a term. The
recorded wording is the one that matters, so whichever is shown, A goes in the record.

A

The cancellation line:

- A. You can still cancel within 14 days and have your money back in full. Asking us to
  start at once does not take that away.
- B. For 14 days after paying you can change your mind and be refunded in full.

A 

Recommended: A. The second sentence answers the question the first one raises.

The renewal line:

- A. Renews each year on this date. We email you before it renews, and you can stop it at
  any time from your account page.
- B. This is a yearly subscription. We email you before it renews, and you can stop it at
  any time from your account page.

B

Recommended: A. Naming the account page turns a subscription into something they control.

## 20. Payment: cash and Monero

- A. Put £20 and this token in an envelope. The token is how we match the money to your
  account, so without it we cannot tell whose it is.
- B. Post £20 with this token. Cash is not refundable by card, so a refund means posting
  the money back.

Both

Recommended: both, in that order. B is the kind of limit this platform states rather than
leaves for someone to discover.

Monero does not take the token. The spec in `docs/planning/specs/prepaid-rails.md` found
that long payment identifiers were removed from the wallet in release 0.15, so attribution
is by a subaddress unique to the account. The page should give the address and say that
the address is the reference, rather than printing a payment identifier that a modern
wallet cannot attach.

The window, and what happens at the end of it.

- A. Your payment window is 14 days, and it is shown on your account page. If the money
  does not arrive in that time the account lapses: mail you already have stays readable,
  your site stays up, and sending, uploading and pushing stop. Nothing is deleted, and
  paying at any time brings it back.
- B.  Your payment window is 14 days, and it is shown on your account page. After that the account will be read-only until we hear from you: mail you already have stays readable,
  your site stays up, but sending new mail and uploading or pushing to your websites stop. Paying at any time will bring it back.

B

Recommended: A. B is friendlier and leaves the reader unsure what "sleeps" means, which is
the ambiguity that generates a support email.

## 21. Account live

Heading.

- A. Your account is live.
- B. You are open for mail.
- C. Everything is ready.

A

Recommended: A, with the second sentence under it saying what to do next.

The line about the first message, which is the one that catches a broken setup:

- A. The first message in your mailbox is encrypted. If you can read it, everything works.
  If you cannot, nothing is lost: the walkthrough has a section for exactly that.
- B. There is one message waiting for you. Being able to read it means you are finished.


A


Recommended: A. It is the difference between a setup that works and a member who quietly
gives up.

The certificate line, which sets a real expectation:

- A. Your certificate has been requested. It usually arrives within a few hours, and until
  then your site answers on HTTP.
- B. Your site is up. The padlock will appear shortly.

A


Recommended: A. B invites the reader to watch for a padlock on a site they cannot yet
reach securely.

## 22. Account page: status, notices and actions

Status labels, which are read by people who are worried about something.

- A. Active. Paid until 30 September 2027.
- B. Everything is in order. Paid until 30 September 2027.
A
Recommended: A. "Everything is in order" reads like a bank, and this page is not a bank.

The notices list, which is the record of what we told them.

- A. This is every notice have written to you across all your addresses.
  
- B. This is everything we have written to you about your account, and everything we will
  write.

  A

Recommended: A. It says where the notices went, which is the part that matters when one
of the addresses was wrong.

The limits of what we can do, which belongs on the page as a short list.

- A. We cannot read your mail. We cannot recover your key. We cannot restore mail you have
  deleted. We cannot give you shell access.
- B. What we cannot do: read your mail, recover your key, restore deleted mail, give you a
  shell.

  A

Recommended: A. Four short sentences, each one a promise kept, which is worth more here
than a colon and a list.

## 23. Key rotation

- A. Replace my mail key. Confirmed from your other address if you gave one, and with
  three days to change your mind either way.
- B. Change the key your mail is encrypted to. Both of your addresses have to confirm it,
  unless you gave only one, and you have three days to stop it.

  A

Recommended: A. The mechanism matters less here than the fact that it cannot be done to
you in a moment.

The explanation of why, which the reader deserves.

- A. We ask because changing the key is how someone who has taken over your mail would
  read everything sent to you afterwards.
- B. This is the one change that can hand your future mail to someone else, so it is
  deliberately slow.


  A

Recommended: A. It explains the risk in the reader's terms rather than ours.

## 24. Closing the account

Heading and the first line.

- A. Closing the account. You can end it now and it will terminate within seven days.
- B. Close my account. Seven days, and you can change your mind in that week.

a and b 

Recommended: A on the page, B on the button. The heading states what the page is, the
button says what pressing it does.

The consequences, which have to be complete:

- A. Mail stops being accepted, your site and capsule stop answering, the account is
  deleted, and your repositories are deleted with it. Copies in our backups expire within
  about seven months. Your username is free again after 90 days.
- B. Everything goes: mail, website, capsule, repositories. Backups fade within about
  seven months. The name comes free after 90 days.

A

Recommended: A. B is quicker to read and drops the detail someone needs to decide, and the
detail is the whole point of the page.

The reminder to take a copy first, which should not be a footnote:

- A. Take a copy of everything first. Your mail comes out encrypted to your key, so you
  will need the key you already hold to read it.
- B. Download your data before you close.

A

Recommended: A. It answers the question the reader will otherwise ask after closing.

## Settled so far

- Section 2, the mail heading: **Secure encrypted mail**. The paragraph under it does not
  change, because that paragraph carries the fact that makes this platform different, and
  the heading is the phrase a reader already recognises.
- Section 10, the recovery phrase: option A, which says who could read the mail and why
  nobody here can help.
- Section 13, the questions about you: both, the line about the door first and the handling
  of the answers after it.
- Section 3, the price line: option B, plus an invitation for a parish to write rather than
  a quoted price, since the parish tier is not priced yet. The mock carries both, and its
  lede was corrected to match.
- The free tier reaches people rather than bodies: clergy, monastics and anyone who cannot
  pay. Whether an institution can be granted an account without charge stays open in
  [#177](https://github.com/kyriakon/kyriakon-infra/issues/177), and the working position is
  that an institution with a treasurer pays.

Every other section stands at the recommended option until it is overruled.


