TARGET-EXPERIMENT-REQUIRED

## Verdict

A same-machine trusted-consent path is plausible, but it is not established on this target.

Linux does not provide a turnkey secure-attention session. The viable candidate combines a reserved VT, enforced DRM/KMS takeover, a dedicated non-desktop UID, a physical approval input device never exposed to the desktop, and a protected live result channel. Its decisive display, input-revocation, and lifecycle properties depend on undocumented behavior of this exact linux-asahi/apple-drm/systemd combination and require controlled testing.

The current host configuration is not safe for this purpose: the desktop user has static raw-input access, can create uinput devices, and already runs a virtual input device.

## Executive assessment

The answer to the central question is:

- **On the machine as currently configured: no.**
- **With a hardened reserved-VT/direct-KMS profile: potentially yes.**
- **Before the named target experiments pass: the Tier 3 claim must remain blocked.**

A separate UID, VT number, logind session, root-owned executable, or systemd “secure attention” signal is individually insufficient. The candidate becomes credible only after:

1. the protected renderer has conclusively taken KMS master and replaced every active scanout surface;
2. approval comes from a device the desktop never held or could inject into;
3. VT/display/input loss cancels before approval-result delivery;
4. the result travels over a process-bound, nonce-bound channel;
5. the user deliberately enters the path through the reserved physical input.

No phone or intelligent external approval application is inherently required. A simple dedicated keypad can provide the physical attention and approval path, if its complete Linux device surface is reserved to the system service.

The existing design selects an external intelligent device at [re.md line 35](/home/swa/src/a-quo/re.md:35). That selection should not yet be replaced; this investigation establishes a concrete local candidate, not completed feasibility.

## Actual target audit

### Platform and software

| Classification | Observed fact |
|---|---|
| TARGET OBSERVATION | Apple MacBook Pro 16-inch, 2021, M1 Max; device-tree identities `apple,j316c` and `apple,t6001`. |
| TARGET OBSERVATION | Arch Linux ARM rolling release. |
| TARGET OBSERVATION | `uname -a`: `Linux alarm 7.1.6-1-1-ARCH #1 SMP PREEMPT_DYNAMIC Sat, 08 Aug 2026 17:14:04 +0000 aarch64 GNU/Linux`. |
| TARGET OBSERVATION | Kernel package: `linux-asahi 7.1.6.asahi1-1`. |
| TARGET OBSERVATION | systemd 261, Arch package `261.2-1-arch`. |
| TARGET OBSERVATION | Hyprland package `0.56.1-3`, build commit `5c9377c15f…`; Aquamarine 0.14.0. |
| TARGET OBSERVATION | `systemd-logind` is active. `seatd` is installed but disabled/inactive. |
| TARGET OBSERVATION | Hyprland links libseat. Its log shows seatd failing and the logind backend being selected. |
| PRIMARY-SOURCE BASIS | Asahi’s feature matrix identifies M1 Pro/Max display controller, GPU, keyboard and related support as Asahi-specific; generic x86 KMS assumptions are insufficient. [Asahi platform support](https://asahilinux.org/docs/platform/feature-support/m1/) |

### Sessions, seat and VTs

| Classification | Observed fact |
|---|---|
| TARGET OBSERVATION | Session 2: user `swa`, UID 1001, `seat0`, `tty2`, VT 2, Wayland, active; started through SDDM. |
| TARGET OBSERVATION | Session 3: user-manager session, active, no seat. |
| TARGET OBSERVATION | Session 4: user `swa`, `tty3`, VT 3, inactive/online. |
| TARGET OBSERVATION | `seat0` reports `CanTTY=yes`, `CanGraphical=yes`, `CanMultiSession=yes`; active session is 2. |
| TARGET OBSERVATION | `/sys/class/tty/tty0/active` reports `tty2`. |
| TARGET OBSERVATION | logind defaults are `NAutoVTs=6`, `ReserveVT=6`; VT6 is only conventionally reserved, not reserved for A Quo. |
| TARGET OBSERVATION | `/dev/tty2` and `/dev/tty3` are owned by `swa:tty`, mode 0600. `/dev/tty1`, `/dev/tty6` and `/dev/tty0` are root-owned. `/dev/console` is root mode 0600. |
| TARGET OBSERVATION | `/dev/vcs*` are `root:tty` mode 0660; `swa` is not in group `tty`. |
| IMPLEMENTATION-SPECIFIC BEHAVIOUR | logind currently controls the graphical VT’s `VT_PROCESS` lifecycle and has been observed sending seat-disable/seat-enable transitions to Hyprland. This is cooperative evidence, not the required hostile test. |

### User authority and device access

The current user is UID 1001 and belongs to:

- `swa`
- `docker`
- `input`
- `wheel`
- `plugdev`

It is not in `video`, `render`, `tty`, `uucp`, or a `seat` group.

The important exception is membership in `input`: it confers static read/write access to all ordinary evdev devices and `/dev/uinput`.

### Display devices

| Classification | Observed fact |
|---|---|
| TARGET OBSERVATION | `/dev/dri/card1`: Asahi AGX GPU, `root:video` 0660 plus a dynamic `uaccess` ACL granting `swa` read/write. It exposes no KMS connectors. |
| TARGET OBSERVATION | `/dev/dri/card2`: `apple-drm` KMS device, `root:video` 0660 plus dynamic `uaccess` ACL for `swa`. |
| TARGET OBSERVATION | `/dev/dri/renderD128`: world read/write, backed by the Asahi GPU. |
| TARGET OBSERVATION | Hyprland holds multiple read/write FDs for `card2` and multiple render-node FDs. |
| TARGET OBSERVATION | Both `eDP-1` and `HDMI-A-1` are connectors on `card2`. They cannot be assigned as independent logind-seat devices. |
| TARGET OBSERVATION | `/dev/fb0` is `appledrmfb`, `root:video` 0660 without a user ACL. |
| TARGET OBSERVATION | The DRM devices carry `seat`, `uaccess`, and `master-of-seat` udev tags. |
| PRIMARY-SOURCE GUARANTEE | DRM has one current master for non-shareable display control; render nodes do not confer modesetting authority. [DRM userspace API](https://docs.kernel.org/gpu/drm-uapi.html), [Linux 7.1 DRM master implementation](https://github.com/torvalds/linux/blob/v7.1/drivers/gpu/drm/drm_auth.c) |
| IMPLEMENTATION-SPECIFIC BEHAVIOUR | systemd 261 drops DRM master for the managed session FD when pausing the session; it does not revoke every independently opened primary-node FD. [systemd v261 session-device code](https://github.com/systemd/systemd/blob/v261/src/login/logind-session-device.c) |

### Input devices

| Classification | Observed fact |
|---|---|
| TARGET OBSERVATION | Physical devices include Apple SPI Keyboard `event1`, trackpad `event2`, power/lid `event0`, and headset input `event3`. |
| TARGET OBSERVATION | `event9` is the virtual `ydotoold virtual device`; `ydotoold` runs as UID 1001. |
| TARGET OBSERVATION | `/dev/input/event*` and `/dev/uinput` are `root:input` mode 0660. UID 1001 therefore has read/write access. |
| TARGET OBSERVATION | The uinput module is loaded. |
| TARGET OBSERVATION | Hyprland holds read/write evdev FDs for the keyboard, trackpad and virtual ydotool device. |
| TARGET OBSERVATION | logind watches both the physical Apple keyboard and the ydotool virtual keyboard for system-button chords. |
| TARGET OBSERVATION | A custom ZSA rule grants vendor `3297` USB devices broad access, including mode 0666/`plugdev` access. The observed Voyager cannot be used as a trusted keypad under that rule. |
| PRIMARY-SOURCE GUARANTEE | uinput deliberately lets userspace create virtual input devices and emit kernel input events. [Kernel uinput documentation](https://docs.kernel.org/input/uinput.html) |
| IMPLEMENTATION-SPECIFIC BEHAVIOUR | `EVIOCREVOKE` revokes one evdev client/open instance. Independently opened clients are not revoked. evdev write calls can inject events into the underlying input device. [Linux 7.1 evdev implementation](https://github.com/torvalds/linux/blob/v7.1/drivers/input/evdev.c) |

### Kernel configuration and sysctls

| Item | Target value |
|---|---|
| `CONFIG_VT` | `y` |
| `CONFIG_VT_CONSOLE` | `y` |
| `CONFIG_VT_HW_CONSOLE_BINDING` | `y` |
| `CONFIG_DRM` | `y` |
| `CONFIG_DRM_KMS_HELPER` | `y` |
| `CONFIG_DRM_FBDEV_EMULATION` | `y` |
| `CONFIG_FRAMEBUFFER_CONSOLE` | `y` |
| `CONFIG_INPUT_EVDEV` | `y` |
| `CONFIG_INPUT_UINPUT` | `m`, loaded |
| `CONFIG_MAGIC_SYSRQ` | `y` |
| `CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE` | `0x0` |
| `CONFIG_SECURITY_YAMA` | `y` |
| `CONFIG_ACCESSIBILITY` | `y` |
| `CONFIG_SPEAKUP` | `m`, not loaded |
| `kernel.sysrq` | `16`; only the sync function class is enabled, not keyboard/SAK functions |
| `kernel.yama.ptrace_scope` | `1` |
| `dev.tty.legacy_tiocsti` | `1` |
| `user.max_user_namespaces` | `128629` |

## Security-property table

This evaluates the observed configuration and the candidate profile separately.

| Property | Current host | Candidate reserved-VT/direct-KMS profile |
|---|---|---|
| Display integrity | **Fail.** Normal consent is an ordinary Hyprland surface. | **Conditional.** Passes only if apple-drm gives the protected process exclusive KMS master, all connectors/planes are replaced with fresh inaccessible buffers, and loss is detected. |
| Input authenticity | **Fail.** UID 1001 can open/write evdev and uinput and already owns a virtual input source. | **Conditional.** Requires a dedicated physical keypad never exposed to the desktop, complete removal of desktop raw/uinput access, and reboot/full-session replacement before qualification. |
| Process integrity | **Fail for current helper.** Same desktop UID can signal and potentially ptrace it. | **Feasible.** Dedicated static UID, root-owned executable/configuration, PID1 supervision and no user-controlled code/configuration. |
| Result authenticity | **Insufficient for Tier 3.** Same-user peers are indistinguishable at the existing boundary. | **Feasible.** Root-owned socket path or inherited anonymous `SOCK_SEQPACKET`, peer credentials, exact process lifetime, nonce and protected-session binding. |
| Lifecycle integrity | **Absent.** Ordinary Wayland lifecycle is not authority. | **Conditional.** Approval must remain unarmed until VT, KMS and input checks pass; every loss before secure result delivery cancels. Target race testing is required. |
| Trusted-path recognition | **Fail.** A fake Hyprland surface is indistinguishable. | **Conditional.** User initiates with a reserved physical keypad unavailable to the desktop, then verifies a post-takeover random challenge and facts. A logo or colour alone has no security value. |
| Confidentiality | Not provided. | Approval facts need not be secret. The candidate must not collect PINs, passphrases or recovery secrets. |
| Availability | Attacker can obscure or disrupt. | Explicit nonclaim. Racing KMS, flooding requests, GPU load or blocking the switch may deny approval but must never produce it. |

## Candidate comparison

| Candidate | Verdict | Decisive reason |
|---|---|---|
| Ordinary Wayland window | Fail | Hyprland controls composition and input; same-user clients can imitate or obscure it. |
| Same-seat reserved VT text UI | Fail by itself | A VT number does not establish scanout ownership, authentic input, or trusted activation. fbcon/apple-drm handoff is unverified. |
| Same-seat separate logind session | Useful coordinator, not sufficient | The session object can manage activation and device FDs, but security depends on actual DRM/input revocation and process identity. |
| Direct KMS process | Required component; target test pending | Current DRM master rules can enforce scanout exclusion after acquisition, but apple-drm handoff and retained-FD behavior need testing. |
| Minimal compositor on a reserved VT | Potentially viable, larger TCB | It can improve layout/accessibility but introduces compositor, protocol, font and client parsing. It is not the minimum initial profile. |
| Kernel/systemd secure-attention-key path | Fail as complete path | Kernel SAK kills console processes; systemd emits a signal. Neither establishes the A Quo display/input path, and the systemd chord is injectable on this host. |
| Separate physical seat | Viable in principle, unavailable on audited hardware | Requires an independent DRM/KMS device plus dedicated input. The internal and HDMI connectors share one DRM device. |
| External intelligent approval device | Viable comparison, not proven necessary | Can supply independent display/input but adds device application, OS, pairing, accessibility and transport assumptions. |

## Kernel/systemd secure-attention findings

Linux currently exposes two differently named facilities:

1. **Kernel `K_SAK` / traditional SAK.** It is a console keymap action intended to kill processes associated with the current console. Kernel documentation expressly warns that it is not a complete trusted secure-attention implementation. It does not launch a fixed service, acquire KMS, allocate input, or produce an A Quo result. [Linux SAK documentation](https://docs.kernel.org/security/sak.html)

2. **Magic SysRq `k`.** It terminates processes on the current virtual console. It likewise does not establish trusted display/input. The target’s `kernel.sysrq=16` disables the keyboard-function class containing this operation. [Magic SysRq documentation](https://docs.kernel.org/admin-guide/sysrq.html)

3. **systemd v261 secure-attention chord.** logind recognizes Ctrl+Alt+Shift+Esc from evdev state and emits `org.freedesktop.login1.Manager.SecureAttentionKey` for the seat. It does not switch VTs or start a fixed protected service. [Chord handling](https://github.com/systemd/systemd/blob/v261/src/login/logind-button.c), [signal emission](https://github.com/systemd/systemd/blob/v261/src/login/logind-action.c)

Answers to the requested questions:

- The systemd action is a system-bus signal. It is not approval authority and can, at most, request activation.
- logind reads input independently of Hyprland, so Hyprland cannot simply suppress a genuine event by withholding a Wayland event.
- On this host, UID 1001 can inject the same chord through uinput or by writing an evdev FD. logind is already monitoring a virtual ydotool keyboard.
- Neither facility selects only a fixed A Quo executable.
- Neither facility transfers the physical display and approval input.
- No usable kernel-level SysRq/SAK gesture was established for the target Apple keyboard.
- A kernel keymap/configuration change, input-permission changes, and privileged service setup would be required.
- Kernel SAK semantics are documented; the systemd chord behavior is version-specific; its usability on this keyboard is unestablished.

There is no `KEY_SAK` evdev code on the target headers. Linux exposes the console keymap function `K_SAK`.

## VT-switch analysis

A protected service can issue `VT_ACTIVATE`, wait with `VT_WAITACTIVE`, inspect `VT_GETSTATE`, and use `VT_LOCKSWITCH`. These operations are controlled by the active console relationship or `CAP_SYS_TTY_CONFIG`. [VT ioctl documentation](https://man7.org/linux/man-pages/man2/ioctl_vt.2.html)

The observed graphical session uses `VT_PROCESS`. systemd 261’s intended sequence is to pause its managed devices and acknowledge release. The kernel’s VT switching and lock implementation can prevent ordinary unprivileged processes from directly changing the active VT, but this is not equivalent to proving the complete graphical handoff. [Linux 7.1 VT implementation](https://github.com/torvalds/linux/blob/v7.1/drivers/tty/vt/vt.c), [VT ioctl implementation](https://github.com/torvalds/linux/blob/v7.1/drivers/tty/vt/vt_ioctl.c)

The decisive question—can the system enter the reserved VT without malicious Hyprland cooperation—has this answer:

**The architecture suggests yes because logind, not Hyprland, owns the target `VT_PROCESS` release protocol, but this has not been demonstrated against a deliberately noncooperating compositor on this exact target.**

Required behavior is:

- root/system service requests VT6;
- a bounded timeout waits for VT6 to become active;
- failure, delay or inconsistent session state cancels;
- input remains disarmed until display takeover;
- `VT_LOCKSWITCH` is applied and active state is rechecked before rendering authoritative facts;
- any later loss before result delivery cancels.

Ctrl+Alt+Fn is not a trusted activation gesture here. A compositor in graphical keyboard mode can consume or imitate it. A fake Hyprland VT-like screen remains possible, but must have no access to the reserved approval input and therefore cannot create approval.

## Display-device analysis

While Hyprland is active, it controls `card2` through logind-provided primary-node FDs. The desktop also has a dynamic ACL permitting independent opens.

On session deactivation, systemd 261 drops DRM master on its managed FD. It does not revoke all independently opened primary-node FDs. Removing the ACL later does not invalidate an FD already opened.

The candidate must therefore use this ordering:

1. deactivate the graphical session;
2. acquire KMS master for the protected renderer;
3. atomically replace every enabled CRTC, plane and connector on `card2`;
4. use a fresh buffer never shared with the desktop;
5. wait for modeset completion;
6. verify continued master/modeset authority;
7. only then arm approval input.

A retained primary-node FD may race to become master before the protected process. That is acceptable only as denial of service: if the protected process does not own master, approval never becomes possible. Once the protected process is current master, another unprivileged FD must not be able to commit scanout changes.

A render-node FD cannot itself modeset. It may continue rendering or cause load/hangs, but must not have a handle to the protected scanout buffer. This leaves denial of service, not false display.

DRM leases do not repair initial trust: a lease is created within the current master’s lease tree. A lease issued by compromised Hyprland would depend on the attacker-controlled compositor.

The internal panel and HDMI connector are both on `card2`. They must be controlled or blanked together. They cannot form independent logind seats merely by assigning connectors.

The unestablished target behaviors are:

- apple-drm master transfer after hostile-session deactivation;
- whether old planes, cursors, imported buffers or leases remain influential;
- atomic replacement of all target outputs;
- notification and cancellation on hotplug, reset or master loss.

## Input-device analysis

The current host fails input authenticity for three independent reasons:

1. UID 1001 is in `input`;
2. `/dev/uinput` is writable by that group;
3. a live ydotool virtual keyboard already exists.

`EVIOCGRAB` does not fix this. It directs events to one evdev client, but an attacker with an independently opened writable FD can inject through the underlying input handle. Likewise, logind’s `EVIOCREVOKE` affects the managed client and its duplicates, not another independently opened client.

The minimum candidate therefore uses a dedicated physical USB keypad:

- its evdev, hidraw, usbfs and sibling interfaces are root/service-only;
- it is never supplied to Hyprland or the desktop logind session;
- the service pins its physical sysfs topology and available stable device identity;
- it opens the device before the operation and does not substitute another device after disconnect;
- it rejects `/devices/virtual/...` and all non-pinned event nodes;
- disconnect, topology change or a new device causes cancellation;
- a neutral-input barrier requires every key to be released after display takeover;
- approval requires a fresh complete press-and-release after that barrier.

The observed ZSA Voyager can be a controlled test article only after its current broad udev rule is removed and all its interfaces are made exclusive. It does not qualify in the observed state.

Other paths:

- A Wayland virtual keyboard affects the Hyprland session, not another VT directly.
- uinput is kernel-global and is dangerous wherever the desktop can use it.
- `TIOCSTI` injects bytes into a TTY line discipline. The candidate ignores TTY input and reads only the pinned evdev device; therefore TIOCSTI cannot approve. Disabling legacy TIOCSTI remains sensible hardening. [TIOCSTI documentation](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)
- The internal keyboard could potentially be transferred after revocation, but its pre-switch writable logind FD makes it unsuitable as the trusted activation device. The dedicated keypad avoids that dependency.
- Confidentiality of non-secret approval keystrokes is not required. No PIN, passphrase or recovery secret should be collected.

## Process-isolation analysis

The consent process cannot run as the desktop UID. `ptrace_scope=1` is not a substitute for a UID boundary, and same-UID signal permissions remain dangerous. [ptrace access rules](https://man7.org/linux/man-pages/man2/ptrace.2.html), [signal permission rules](https://man7.org/linux/man-pages/man2/kill.2.html)

The minimum process split is:

- a root-owned, PID1-managed supervisor responsible only for VT/session and device setup;
- a static non-root `aquo-consent` UID distinct from both UID 1001 and the authority UID;
- a root-owned fixed executable, libraries, font and configuration;
- no home-directory access, network, user session bus, desktop environment, user-selected plugins or executables;
- no user-writable environment or search paths;
- no general proof, persona-database, signer, archive, media, wallet, package or plugin parsing;
- one bounded already-derived consent request in, one decision out.

The renderer should not need ambient capabilities. Device FDs should be opened or arranged by the minimal supervisor and inherited. `CAP_SYS_TTY_CONFIG` belongs only in the smallest VT-management component. Any target-specific need for `CAP_SYS_ADMIN` must be proven and confined rather than assumed.

## Result-channel analysis

The minimum result path is local and process-bound:

- the authority connects to a socket in a root-owned `/run` directory or receives a connected anonymous `AF_UNIX/SOCK_SEQPACKET` endpoint;
- the system service validates authority-side peer credentials;
- the authority validates the service peer’s kernel credentials;
- PID1/root supervisor launches the exact root-owned service;
- the child receives a fresh anonymous endpoint, not a caller-selected path;
- messages are single-record and bounded.

Linux supplies peer credentials for connected Unix sockets and optional per-message credentials. [Unix-domain socket documentation](https://man7.org/linux/man-pages/man7/unix.7.html)

A result must bind:

- request nonce;
- operation type;
- persona;
- canonical statement digest;
- expiry;
- approve, decline or cancel;
- protected-session instance;
- protocol version.

The protected-session instance is unique per process/device acquisition and is never reusable. The authority consumes one terminal result exactly once.

If the desktop opens a public request endpoint first, it can only request that secure mode be considered. It cannot reach the result endpoint. A private endpoint accepts only the configured authority UID.

The approval linearization point is secure delivery and acknowledgement of the complete result while the protected session remains active. Any VT, KMS, input or process loss before that point yields only cancel. Normal teardown after acknowledgement does not invalidate the already-delivered approval.

## Human trusted-path analysis

The minimum truthful procedure is:

1. A pending A Quo request exists, but no approval is possible.
2. The user deliberately presses the reserved physical attention key on the dedicated keypad.
3. The root supervisor switches to the protected VT.
4. The screen blanks and is fully redrawn only after protected KMS ownership.
5. The protected process displays:
   - operation;
   - persona;
   - exact purpose/namespace;
   - statement summary and full inspectable values;
   - key/provider facts;
   - digest where relevant;
   - a newly generated session challenge.
6. The user pages through the real protected display.
7. Only after all keys were observed released does the service accept a fresh approve or decline sequence from the reserved keypad.
8. The protected result is delivered and acknowledged.
9. The supervisor releases devices and returns to the previously active session.

A fixed phrase, colour, icon or imitation terminal is not authentication. The meaningful facts are:

- the user used a physical input unavailable to the desktop;
- that input is ignored for approval unless protected KMS ownership is established;
- the displayed session challenge is generated after takeover;
- a fake Hyprland screen cannot turn keypad activity into an approval result.

If the real switch is blocked, the user may see a convincing fake screen, but the authority receives no approval. That is confusion or denial of service, not false approval.

## Same-seat verdict

**Not passed on the observed configuration; conditionally viable pending tests.**

The first present failure is input authenticity: UID 1001 can inject kernel input through evdev and uinput.

After correcting that, the first unresolved feasibility question is whether linux-asahi/apple-drm and systemd 261 mechanically transfer and retain exclusive scanout control while old desktop FDs remain open.

An internal-keyboard-only profile is not recommended: its activation path is forgeable before handoff. The candidate uses the same physical display but a dedicated system-only keypad.

## Separate-seat verdict

**Not available on the audited hardware configuration.**

The internal panel and observed HDMI output are connectors on the same `apple-drm` card. logind seat assignment operates on the device, not an individual connector. A DRM lease would depend on compromised Hyprland.

A genuine separate physical seat would require:

- an independent DRM/KMS device or a separately managed physical terminal;
- a dedicated keyboard/keypad;
- root-owned permanent seat assignment;
- no desktop permissions for either device;
- its own protected session and renderer.

A qualified USB display adapter or serial terminal might provide this, but no such device was present or validated. This investigation therefore does not select the separate-seat verdict.

## Minimum practical architecture

This is the one candidate to test; it is not yet approved for implementation.

```text
UNTRUSTED DESKTOP — UID 1001
  Hyprland, CLI, applications
       |
       | bounded request only
       v
A QUO AUTHORITY — dedicated authority UID
       |
       | root-owned SOCK_SEQPACKET launch/result path
       v
SYSTEM CONSENT SUPERVISOR — PID1-managed, root/minimal capability
       |-- activates and locks reserved VT6
       |-- coordinates logind deactivation
       |-- acquires / passes apple-drm KMS FD
       |-- opens pinned dedicated keypad
       |
       v
PROTECTED CONSENT PROCESS — dedicated aquo-consent UID
       |-- direct KMS renderer, fixed font/schema
       |-- one bounded consent request
       |-- fresh session challenge
       |-- pinned evdev input only
       |-- no DB, signer, proof parser, network or user config
       |
       +---- physical display: card2, all connectors/planes
       +---- physical input: dedicated root-only keypad
       |
       | nonce/session-bound terminal result
       v
A QUO AUTHORITY
       |
       +---- existing signing-authority work continues outside this process
```

Required deployment properties:

- VT6 is root-reserved; no getty or user ownership.
- The supervisor and service definitions are root-owned.
- The renderer runs as a distinct static UID.
- Desktop raw evdev, hidraw, usbfs and uinput authority is removed.
- All preexisting desktop raw-input/virtual-device FDs are eliminated by full logout/reboot before enabling the profile.
- The dedicated keypad is not part of Hyprland’s seat and is never handed to it.
- `card2` is acquired only after the desktop session is deactivated.
- The renderer controls or blanks every `card2` connector and plane.
- Approval is disarmed until VT, KMS, display, input and neutral-key checks all pass.
- Every lifecycle loss before result acknowledgement cancels.
- The supervisor returns to Hyprland only after terminal acknowledgement or cancellation.

Excluded attacker: root/administrator, kernel compromise, malicious firmware, and independent physical attacker. Availability remains excluded.

The TCB consists of the kernel VT/input/DRM subsystems, apple-drm/Asahi drivers, systemd-logind/PID1, the root supervisor, direct renderer/font, device rules, loader/libraries, protected socket protocol, keypad and physical display.

## Attack matrix

The rows below describe the candidate after permission hardening. “Test” identifies behavior that is not yet established on the target.

| Hostile scenario | Candidate outcome and enforcement |
|---|---|
| Fake A Quo window in Hyprland | Cannot emit approval. The reserved keypad is accepted only after protected-state checks. User confusion/DoS remains. |
| Hyprland overlay/layer-shell surface | Cannot overlay after protected KMS takeover. Before takeover, approval is disarmed. **DRM test required.** |
| Malicious compositor refuses VT release | Root/logind activation must either complete or time out and cancel. **VT test required.** |
| Retained DRM primary-node FD | May race acquisition and cause DoS; must not modeset after protected master is established. **DRM test required.** |
| Retained render-node FD | Cannot modeset; protected buffer is fresh and unshared. GPU exhaustion/hang remains DoS. |
| Retained evdev FD | Fatal if it references accepted approval input. Candidate keypad is never exposed; shared-device revocation behavior still receives a negative test. |
| Desktop process with uinput | Current host fails. Candidate requires permission removal, elimination of existing uinput devices, and rejection of virtual syspaths. **Test required.** |
| TIOCSTI attempt | Injects only TTY bytes; renderer ignores TTY input. TTY experiment confirms no decision transition. |
| Wayland virtual-keyboard injection | Confined to Hyprland; protected process reads only dedicated evdev. |
| User process switches VTs | `VT_LOCKSWITCH`, root ownership and active-state checking prevent or detect it. Loss cancels. **Race test required.** |
| User process switches sessions | Cannot produce approval; active-session loss cancels. **Lifecycle test required.** |
| User process writes reserved TTY | Root-only device permissions; renderer does not trust TTY input. |
| Same-user ptrace | Different UID plus service hardening denies it. |
| Same-user signals | Different UID denies ordinary signal control. |
| Fake system socket | Root-owned runtime directory and kernel peer credentials; authority does not trust a user path. |
| Fake consent executable | PID1 invokes only root-owned executable, libraries, font and configuration. |
| Result-message replay | Nonce, session instance, expiry and one-use consumption reject it. |
| Stale approval nonce | Rejected before any signing authority is exercised. |
| Session deactivated during key-down | Neutral-key barrier and active-state final check; interruption before delivery cancels. |
| Display disconnect | DRM event or failed final modeset check cancels; device is not substituted mid-request. |
| Input-device disconnect | HUP/removal cancels; no reopen or replacement during the request. |
| Consent-process crash | Socket HUP and PID1 supervision yield cancel; no terminal approval exists. |
| Attacker-triggered repeated prompts | Rate/queue policy may limit DoS. Each prompt still requires reserved physical activation and review. |
| Attacker returns to Hyprland and shows fake success | No effect on authority state. Only authority result/proof evidence is authoritative. |
| Accessibility client attempts approval | Accessibility interfaces are output/navigation only and cannot construct the decision record. |
| Remote desktop active in Hyprland | Cannot access protected KMS/input under the candidate. It may cause DoS before takeover. |
| Dynamically attached virtual input device | Ignored because the service accepts only the already-open pinned physical device; appearance may conservatively cancel. |

## Accessibility assessment

A direct-KMS renderer can support:

- full operation from the dedicated keyboard/keypad;
- visible focus;
- large text and high contrast;
- pagination and reflow;
- full inspection of long labels, fingerprints and digests;
- explicit decline, cancellation and timeout.

It does not automatically provide:

- AT-SPI integration;
- screen-reader speech;
- magnification beyond what the renderer implements;
- switch access;
- braille output.

The kernel has Speakup available as a module, but it is not loaded, and a direct-KMS UI bypasses the kernel text console. Current audio devices are dynamically available to the desktop session, so ordinary desktop speech output is not a protected channel.

A production profile must select one of:

- protected speech inside the consent service with an output device unavailable to the desktop;
- a protected braille/switch device treated as read-only output or qualified input;
- a larger protected compositor/accessibility stack on the reserved VT;
- a separate physical-seat accessibility path.

Accessibility output may disclose facts but must not approve. Alternative input that can approve must meet the same physical pinning and desktop-exclusion rules as the keypad.

Until at least one screen-reader-capable protected path is designed and validated with issue #6, this is a production release constraint, not a feature to silently omit.

## Primary-source guarantees

### Specification and kernel guarantees

- VT activation, active-state queries, process mode and switch locking are defined by the VT ioctl API. [VT ioctls](https://man7.org/linux/man-pages/man2/ioctl_vt.2.html)
- Only the current DRM master has non-shareable modesetting authority; render nodes do not grant it. [DRM UAPI](https://docs.kernel.org/gpu/drm-uapi.html)
- uinput creates kernel-visible virtual input devices. [uinput](https://docs.kernel.org/input/uinput.html)
- Unix-domain sockets expose kernel-derived peer credentials and preserve packet boundaries with `SOCK_SEQPACKET`. [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html)
- Linux SAK and SysRq do not claim to establish the complete trusted path required here. [SAK](https://docs.kernel.org/security/sak.html), [SysRq](https://docs.kernel.org/admin-guide/sysrq.html)

### Implementation-specific behavior

- systemd 261 watches evdev for Ctrl+Alt+Shift+Esc and emits a bus signal.
- systemd 261 uses `EVIOCREVOKE` for a managed evdev client and DRM drop/set-master behavior for managed DRM FDs.
- Linux 7.1 evdev revocation is client-specific; independent opens survive.
- Hyprland 0.56.1 uses the logind backend on this machine.
- apple-drm supplies the target KMS device.

### Target observations

- Input/uinput access is currently available to UID 1001.
- A virtual ydotool input device is active.
- DRM card ACLs are dynamic logind/uaccess ACLs.
- Hyprland holds several card2 and evdev FDs.
- seatd is inactive.
- the active graphical session is VT2 on seat0.
- both observed display connectors belong to card2.
- no independent display device or secure keypad was configured.

### Inferences requiring validation

- Root/logind can complete the VT release despite a malicious compositor.
- A protected KMS owner can fully replace apple-drm scanout and exclude retained desktop FDs.
- A dedicated root-only keypad can remain outside all desktop input paths.
- the active-state/result-delivery ordering can close every deactivation race.
- a random post-takeover challenge plus reserved physical input provides adequate human recognition.

### Unestablished

- No current specification composes VT, logind, DRM and evdev into a Linux secure-attention guarantee.
- No tested protected screen-reader path exists.
- No qualified simple approval keypad has been selected.
- No independent DRM device for a separate seat is present.
- No target evidence establishes apple-drm behavior under hostile retained descriptors.

## Required controlled experiments

All experiments require explicit owner authorization and a disposable or recoverable installation matching the M1 Max, linux-asahi 7.1.6, systemd 261 and Hyprland 0.56.1 target. They were not run during this review.

A second SSH/admin session is required wherever networking survives. Apple recovery media or another known boot path and a verified backup are required for display/VT experiments. Retain monotonic logs, `journalctl`, relevant `dmesg`, session/device state, ioctl results and exact package/kernel hashes.

| Experiment | Question and method | Disruption and rollback | Success / failure |
|---|---|---|---|
| E1 — hostile VT release | Run a disposable compositor/session that ignores pause/release indications; use a small privileged VT helper to request VT6 and record `VT_GETSTATE`, logind session state and timeout. | Screen switch/black-screen risk. SSH watchdog returns to VT2; otherwise restart display manager or reboot through recovery. | Success: VT6 becomes active and the old session becomes inactive without compositor cooperation. Failure: compositor can retain active graphical control while approval might arm. |
| E2 — retained DRM FDs | Hold managed, independently opened primary-node, render-node and lease FDs; deactivate the session; let a protected helper acquire master and perform complete atomic replacement. Attempt old-FD modesets and modification of old/new buffers. | High black-screen/GPU-hang risk. SSH watchdog restores modeset or reboots. | Success: old FDs cannot alter any protected plane after takeover; protected fresh buffer remains exclusive. Failure: any post-arm overlay or modification blocks same-seat feasibility. |
| E3 — retained evdev FDs | Under proposed permissions, obtain the normal logind FD, duplicate/pass it, attempt an independent open, deactivate, then test read/write and a fresh protected FD. | Temporary keyboard loss. SSH/admin session mandatory; reboot restores. | Success: all desktop-held accepted-device clients are revoked or were impossible to obtain. Failure: any desktop FD can generate an accepted approval event. |
| E4 — uinput across sessions | Create a virtual input device before transition in a disposable baseline, then test the hardened configuration after logout/reboot. Attempt injection while protected VT is active. | Synthetic input and possible unintended keys; perform without sensitive applications. Reboot and remove temporary configuration. | Success: desktop cannot create/retain uinput and protected process rejects every virtual source. Failure: synthetic event reaches approval state. |
| E5 — TIOCSTI | Use an isolated test TTY and attempt `TIOCSTI` while the renderer accepts only pinned evdev input. | Possible injected terminal bytes; use nonprivileged disposable TTY. Close PTYs or reboot. | Success: injected bytes never alter consent state. Failure: any TTY byte can approve. |
| E6 — process isolation | Run disposable desktop-UID and consent-UID processes; attempt signals, ptrace, `/proc/*/mem`, environment/config replacement and service control. | No desktop disruption expected. Stop disposable test units. | Success: all control attempts fail except allowed metadata reads. Failure: desktop UID can alter or drive the consent process. |
| E7 — lifecycle cancellation | Interrupt at each boundary: before/after VT activation, KMS acquisition, neutral input, key-down/up, result send and result acknowledgement. Simulate VT/session loss, display disconnect and keypad removal. | Repeated switching/device loss. SSH watchdog and deterministic supervisor cleanup required. | Success: every pre-delivery loss has exactly one cancel and no approval. Failure: stale or post-interruption approval is accepted. |
| E8 — result forgery | Race a fake socket, connect first, send wrong credentials, modify each binding, replay terminal packets, reuse stale sessions and kill the child mid-message. | No device use needed if protocol harness is isolated. Remove runtime directory/test units afterward. | Success: only the PID1-launched process lifetime can provide one matching result. Failure: user-created peer or replay is accepted. |
| E9 — reserved-VT ownership | Before/during activation, have UID 1001 attempt opens/writes to tty6, vcs nodes and VT ioctls. Verify owner/mode and controlling-TTY behavior throughout. | Possible console corruption/switch. SSH watchdog required; restore getty/display state or reboot. | Success: desktop cannot write, reconfigure or switch the reserved VT, and any unexpected state cancels. Failure: desktop can affect rendered authority or active state. |
| E10 — SAK behavior | On the target keyboard and a dedicated keypad, test kernel `K_SAK`, SysRq and systemd’s chord separately; repeat through ydotool/uinput and evdev write under the existing configuration. | May kill console processes; use disposable session with SSH/recovery. Restore keymap/config and reboot. | Expected result: systemd activation is synthesizable and remains request-only; only the reserved keypad can initiate the candidate. Any path that treats the systemd signal as approval fails. |

E1, E2, E3, E4, E7 and E9 are verdict-gating for the same-seat profile. E5, E6 and E8 validate supporting boundaries. E10 confirms that generic SAK facilities are not being overclaimed.

## Effect on issue #68

Issue #68 should **remain blocked pending the exact target experiments above**, principally E1–E4 and E7.

It should not yet:

- adopt the same-seat path as proven;
- declare an external phone mandatory;
- claim systemd secure attention as the consent mechanism;
- treat the current input configuration as qualifiable.

If the gating experiments pass and a protected accessibility path is accepted, issue #68 can adopt the reserved-VT/direct-KMS/dedicated-keypad profile. If KMS exclusion fails, the next local option is an independent physical display/input seat; if that is unavailable, retain the external approval-device architecture.

Issue [#68](https://github.com/SurreptitiousFabric/a-quo/issues/68) remains design-only. Issue [#69](https://github.com/SurreptitiousFabric/a-quo/issues/69) remains the Tier 2 validation work and must not claim this Tier 3 property.

## Proposed narrow re.md change plan

Do not edit yet. If the target evidence supports this result, only these sections need revision:

1. **§1.1, lines 35–69:** make the verified local reserved-VT/KMS profile an allowed consent mechanism instead of requiring an intelligent external device.
2. **§2, lines 106–125:** condition the Tier 3 claim on the exact tested local profile, device permissions and target kernel/driver versions.
3. **§3.1–§3.4, lines 129–242:** replace the external-device edge with the supervisor/consent-UID/VT/KMS/keypad boundary and record why SAK, UID and VT alone fail.
4. **§11.3–§11.6, lines 1129–1202:** specify activation, device handoff, approval linearization, cancellation, downgrade and availability/nonclaim rules.
5. **§12, lines 1204–1323:** add the hostile VT, retained DRM/evdev, uinput, TIOCSTI, fake-socket and lifecycle vectors.
6. **§13, lines 1325–1366:** insert the target feasibility gate before any authority-service implementation.
7. **§14, lines 1368–1436:** replace the assumed external-device decision with the conditional local profile, exact dedicated-input dependency and accessibility decision.
8. **§15–§16, lines 1443 onward:** update only the secure-consent disposition and anti-slop audit.

Authority receipts, migration, signer providers, wallet integration, Plug & Prejudice, gpgv and portable-proof semantics are outside this investigation.

## Final state

- Origin/main reviewed: `a10a371f2bed300a78beabc72f58bf27abc31b8d`
- Current branch: `issue-65-prepare-isolated-gpgv-runtime`
- Current HEAD: `bd139ffe48a5c2834698a82e4d0c94394b81d6f7`
- Reviewed design: [re.md](/home/swa/src/a-quo/re.md)
- `re.md` status: untracked, unstaged, unchanged
- `re.md` SHA-256: `0386ec2df46e731408fd120109b204ffcbe60bef3d876368d873ccfadf7f7539`
- Tracked worktree diff: clean
- Index/staging diff: clean
- GitHub objects and Project fields changed: none
- System configuration or service/device state changed: none
- The required `git fetch origin` refreshed Git fetch metadata only; origin/main did not advance.
- Read-only commands used included `git status`, `git rev-parse`, `git show`, `git ls-files`, `git diff`, `sha256sum`, `stat`, `id`, `uname`, package/version queries, `systemctl status/cat`, `loginctl` queries, `ls/stat/getfacl`, `udevadm info`, `/proc`/`/sys`/kernel-config reads, `rg`, `ldd` and journal inspection.
- No VT/session switch, DRM/input/TTY open-for-use, device grab, service operation, permission change, privileged command, or device experiment was performed.
- Final verdict: `TARGET-EXPERIMENT-REQUIRED`
- Unresolved architecture blockers: **3** — target display/VT exclusion, target input/lifecycle validation, and a protected accessible-output path.
- Required target experiments: **10**.
