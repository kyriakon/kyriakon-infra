The Consumer Contracts Regulations 2013 reg 16 confirmation now reaches an applicant who gave no address outside the platform, on both approval paths. The person approval mail to the newly provisioned mailbox carries `confirmation_body()`. The body approval mail does the same, appended under the same `outside_address.is_none()` rule, so the confirmation reaches the site owner's mailbox on the body's own domain. One `with_confirmation` helper owns that rule for both.

`confirmation_body()` now states the trader identity and geographic address (`cfg.postal_address`), the price and one-year period (person `price_gbp`, group `group_price_gbp`, no-charge says no charge), and the Schedule 3 Part B model cancellation form from `docs/terms.md`. The existing immediate-supply request, accepted document versions and 14-day cancellation summary stay.

An applicant who gave an outside address still gets the separate `confirm()` email, and neither approval mail repeats it.

## Tests

`cargo test --manifest-path control/Cargo.toml -p kyriakon-control-drain --lib`, `cargo test --manifest-path control/Cargo.toml --lib`, `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings` pass. New unit tests cover the no-address person approval mail, the outside-address mail omitting the confirmation, no-charge wording, the group price and the group approval mail.

`an_approval_without_an_outside_address_carries_the_confirmation` requires the confirmation, the cancellation form and the absence of a separate confirmation subject. `a_body_approval_without_an_outside_address_carries_the_confirmation` files a body application with no outside address, approves it, and asserts the mail to `parish-secretary@parish.example` carries the confirmation with no separate confirmation mail. The `group::` integration module passes locally: 63 passed.

## Deploy

Run `deploy-control` and restart the drain.

## Remaining legal text

This is the code-side half only. Still open in #611:

- B2B liability exclusions in `docs/terms.md`.
- Sanctions wording in `docs/terms.md` against what the form collects.
- Prepaid VAT and India OIDAR country evidence in `docs/privacy.md` and `docs/terms.md`.
- Stale status text in `docs/transparency.md` and the representative requirement in `scripts/render-docs.sh`.

Part of #611
