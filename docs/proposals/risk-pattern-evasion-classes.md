# Risk-pattern evasion classes, and the case for a normalization pass

**Status:** proposal, for Rome. No code changes here — this is the design argument
behind a set of already-filed bugs.
**Evidence:** empirical sweep of every CRITICAL / HIGH / MEDIUM pattern in both
implementations at v0.10.0.
**Related beads:** `sable-urvj` (fixed, gated), `sable-5adm`, `sable-mktm`, `sable-7dfe`.

## Why this document exists

`sable-urvj` looked like one bug: `rm --recursive --force /` rated `low` because
the rules spell rm's flags only the short way. Fixing it raised a better
question — *is that rule unusual, or is the whole table built on the same
assumption?* So rather than reason about the regexes, I swept them: for each
rule, run commands that are semantically equivalent to (or strictly worse than)
something the rule already catches, and record where the tier drops.

Three distinct failure classes came out, and they do not have the same shape.
Two are narrow and belong in point fixes. One is systemic and is the reason for
this proposal.

## The classes

### Class A — one spelling of a many-spelled thing (systemic)

A rule names one form; the shell accepts several that mean the same thing. Six
rules affected. Full results in `sable-mktm`; the shape:

| rule | caught | equivalent, and missed |
| --- | --- | --- |
| `dd\s+if=.*of=/dev/sd` | `dd if=/dev/zero of=/dev/sda` — critical | `dd of=/dev/sda if=/dev/zero` — **low** (dd operands are order-free) |
| | | `…of=/dev/nvme0n1` / `vda` / `hda` / `mmcblk0` / `disk0` — **low** |
| `>\s*/dev/sd` | `> /dev/sda` — critical | `> /dev/nvme0n1`, `> /dev/vda`, … — **low** |
| `chmod\s+777` | `chmod 777 f` — high | `chmod -R 777 /` — **medium**; `chmod 0777 f`, `chmod a+rwx f` — **medium** |
| `curl.*\|\s*(bash\|sh\|zsh\|dash)` | `curl … \| bash` — high | `curl … \| sudo bash` — **medium**; `\| python3`, `\| perl`, `\| node` — **low** |
| `kill\s+-9` | `kill -9 123` — medium | `kill -KILL`, `kill -s KILL`, `kill --signal=KILL` — **low** |
| fork bomb literal | `:(){ :\|:& };:` — critical | `:() { :\|:& };:`, `:(){ :\|: & };:` — **low** (valid bash) |

Note the recurring inversion, the same one that made `sable-urvj` a P1: the
missed form is often *more* dangerous than the caught one. `chmod -R 777 /`
rates below `chmod 777 f`. `curl … | sudo bash` rates below `curl … | bash`.
`/dev/sd` is SCSI/SATA — on a current laptop or any cloud VM, the disk you would
actually destroy is `nvme0n1` or `vda`, and those are the ones rated `low`.

The device-family gaps are the most alarming operationally: two CRITICAL rules
whose whole job is "don't let anything write to a raw disk" do not know what
disks are called on the hardware people run.

### Class B — terminator gaps (narrow, already filed)

A rule anchors the end of its match on `(\s|$)`, and a chain operator is in
neither set, so appending one character drops an unconditional hard-block to a
tier policy *can* opt out of:

```
rm -rf /     -> critical
rm -rf /;    -> high     rm -rf /|cat -> high     rm -rf /&& ls -> high
rm -rf /etc; -> high     rm -rf /)    -> high     rm -rf />f    -> high
```

I swept this axis across every critical and high rule to find out whether it is a
class or an instance. **It is bounded: only the four `rm` patterns.** Every other
critical rule has no trailing anchor at all, so there is nothing to gap. Filed as
`sable-5adm`, and it stays a point fix — widening those four terminators to the
same `[\s;&|)]` token-end class the `sable-urvj` normalizer already uses.

### Class C — over-match on bare substrings (narrow, already filed)

The inverse direction, and the most user-visible. `mkfs`, `fdisk`, and `parted`
are bare substrings with no word boundary and no command-position anchor, at the
tier that documents itself as "no policy, mode, or deny-list can opt out":

```
vim departed.md          -> critical      man parted          -> critical
./sfdisk-wrapper.sh      -> critical      which mkfs          -> critical
pytest tests/test_fdisk.py -> critical    npm i parted-utils  -> critical
```

`vim departed.md` is an ordinary editor command on an ordinary filename, and it
is unconditionally blocked by a tool that ships inside agent hooks. Filed as
`sable-7dfe`. The sanitizer already rescues the data-shaped cases (`echo mkfs`,
`grep -r mkfs docs/` correctly rate `low`), so what remains is genuine
over-match in command position.

## The proposal

Classes B and C are point fixes; they are filed and should land as such.

Class A should not be. The instinct is to patch each of the six rules — add
`nvme|vda|hda|mmcblk|disk` to the device alternation, add `python|perl|ruby|node`
to the interpreter list, add `0777|a+rwx` to chmod, and so on. That is six
patches that each restate the same idea, and the seventh spelling re-opens every
one of them. It is the approach I rejected inside `sable-urvj`, for the same
reason, at a smaller scale.

`sable-urvj` shipped the alternative and it worked: **normalize the command, then
match.** One pass rewrote each `rm` flag run to a canonical short cluster, the
pattern table was left untouched, and every existing and future `rm` rule
inherited long-flag coverage. The differential over ~7,600 commands showed zero
lost detections.

The proposal is to generalize that pass — a single `canonicalizeCommand()` stage
between the existing sanitizer and the pattern table, absorbing the equivalences
the shell already treats as equivalent:

- **flag forms** — long to short, `--flag=value` to `--flag` (the `sable-urvj`
  pass, widened past `rm`);
- **argument order** for commands whose operands commute (`dd`'s `if=`/`of=`);
- **device families** — a named `RAW_DISK_DEVICE` alternation used by every rule
  that means "a raw disk", instead of each rule spelling `/dev/sd` itself;
- **interpreter and privilege wrappers** — `| sudo -E bash` normalizes to
  `| bash`, so pipe-to-shell rules stop caring what sits between;
- **whitespace** inside literal payloads like the fork bomb.

The point is not that these five are the complete list. It is that each one
becomes a property of the *normalizer*, stated once, rather than a property of
every rule that happens to touch it. New rules inherit it. That is what makes the
table maintainable, and it is the difference between fixing six bugs and fixing
the reason there were six.

### What this costs, honestly

A normalization pass is a place for bugs to hide, and its failure mode is silent.
Two disciplines are non-negotiable, both already demonstrated on `sable-urvj`:

1. **Every change verified by old-vs-new differential over a real corpus**, with
   lost detections enumerated, not just green tests. Green tests show the new
   cases pass; the differential shows the several thousand you were not thinking
   about did not regress.
2. **Normalization runs after the sanitizer, never before.** The sanitizer is
   what keeps a quoted commit message from being read as a command. Canonicalizing
   before it would let prose be normalized into a live-looking command.

There is also a scope question this proposal does not settle, carried over from
`sable-urvj`: user-authored `.rafter.yml` policy patterns currently match against
the un-normalized command. Normalizing them too closes the same evasions for user
deny rules, but silently kills a rule written `deny: "rm --recursive"`. Doing it
properly means validating policy patterns against the canonicalization at load
time and warning when one can no longer match. That is a real design decision and
belongs to whoever takes this on.

## Recommendation

1. Land `sable-5adm` (class B) and `sable-7dfe` (class C) as point fixes, each on
   its own branch and gate — they are independent and small.
2. Treat `sable-mktm` (class A) as a design task, not a patch task. If the
   normalizer generalization is accepted, the six rules in the table above become
   its test matrix rather than six separate fixes.
3. Whatever lands, hold it to the differential. On a detector, a passing test
   suite is not evidence.
