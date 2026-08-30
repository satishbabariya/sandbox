import Containerization
import ContainerizationEXT4
import ContainerizationOCI
import ContainerizationOS
import Darwin
import Foundation
import Logging
import SystemPackage

/// The wrappers that turn a guest command into the command actually run.
///
/// Each takes an argv and returns one that does something first and then
/// execs what it was given, so they compose. Applying one last makes it
/// outermost, which makes it run first -- the reverse of how they read, and
/// the source of more than one bug here.
///
/// They are pure: argv in, argv out, nothing touched. That is what makes the
/// quoting and the ordering testable without booting anything.
extension Sandbox {
    /// Start dockerd in the background, wait for its socket, then exec the
    /// real command. Failing to start is reported rather than silently
    /// leaving the agent with a broken docker.
    static func dockerBootstrap(wrapping command: [String]) -> [String] {
        guard !command.isEmpty else { return command }
        // The stock guest kernel does not expose the nf_tables netlink API, so
        // the nft-backed iptables shim fails with "Could not fetch rule set
        // generation id" and dockerd cannot create its NAT chain. The legacy
        // backend works, so select it when nft is broken rather than requiring
        // a custom kernel.
        let script = """
            if ! iptables -t nat -L >/dev/null 2>&1; then
              for tool in iptables ip6tables; do
                if [ -x "/usr/sbin/$tool-legacy" ]; then
                  ln -sf "/usr/sbin/$tool-legacy" "/usr/sbin/$tool" 2>/dev/null
                  ln -sf "/usr/sbin/$tool-legacy" "/sbin/$tool" 2>/dev/null
                fi
              done
            fi
            if command -v dockerd >/dev/null 2>&1; then
              mkdir -p /var/log
              dockerd --host=unix:///var/run/docker.sock >/var/log/dockerd.log 2>&1 &
              for i in $(seq 1 60); do
                if docker info >/dev/null 2>&1; then break; fi
                sleep 0.5
              done
              if ! docker info >/dev/null 2>&1; then
                echo "sandbox: dockerd did not start; see /var/log/dockerd.log" >&2
              fi
            else
              echo "sandbox: --docker given but dockerd is not in this image" >&2
            fi
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "sandbox"] + command
    }

    /// Write the MCP configuration, then exec.
    ///
    /// The JSON goes through base64 so quoting in server arguments cannot break
    /// the shell that writes it.
    static func mcpBootstrap(
        wrapping command: [String], path: String, contents: String
    ) -> [String] {
        guard !command.isEmpty else { return command }
        let encoded = Data(contents.utf8).base64EncodedString()
        let script = """
            mkdir -p "$(dirname \(path))"
            printf %s '\(encoded)' | base64 -d > "\(path)" 2>/dev/null \
              || echo "sandbox: could not write \(path)" >&2
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "sandbox"] + command
    }

    /// Create an unprivileged user if the image lacks one, hand it the
    /// workspace and a home, and exec the command as that user.
    ///
    /// Applied last so the CA install, MCP config, clone and dockerd bootstraps
    /// have all completed their root-only work first.
    static func dropPrivilegeBootstrap(
        wrapping command: [String], user: String, workspace: String, cloned: Bool
    ) -> [String] {
        guard !command.isEmpty else { return command }
        // A cloned workspace is a real tree in the rootfs, created moments ago
        // by the clone step running as root, so the agent cannot write it until
        // it is chowned. A shared workspace is virtiofs, which presents host
        // ownership whatever the guest asks for: recursing there changed
        // nothing and still walked every file, which cost 20s of startup on a
        // 45k-file repository.
        let workspaceOwnership =
            cloned ? "chown -R \"$TARGET_UID\" \"\(workspace)\" 2>/dev/null || true" : ":"
        let script = """
            RUN_AS=\(user)
            if ! id -u "$RUN_AS" >/dev/null 2>&1; then
              # Many agent images already ship an unprivileged user at 1000 —
              # node:22 has "node" — and creating another there fails as
              # non-unique. Reuse whoever is already there.
              EXISTING=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
              if [ -n "$EXISTING" ]; then
                RUN_AS="$EXISTING"
              else
                # busybox/alpine and shadow/debian disagree on flags, so try
                # both and keep their usage output off the agent's stdout.
                adduser -D -u 1000 "$RUN_AS" >/dev/null 2>&1 \
                  || useradd -m -u 1000 -s /bin/sh "$RUN_AS" >/dev/null 2>&1 \
                  || true
              fi
            fi
            TARGET_UID=$(id -u "$RUN_AS" 2>/dev/null)
            if [ -z "$TARGET_UID" ]; then
              echo "sandbox: no unprivileged user available; running as root" >&2
              exec "$@"
            fi
            TARGET_GID=$(id -g "$RUN_AS" 2>/dev/null || echo "$TARGET_UID")
            HOME_DIR=$(getent passwd "$RUN_AS" 2>/dev/null | cut -d: -f6)
            [ -n "$HOME_DIR" ] || HOME_DIR=/home/"$RUN_AS"
            mkdir -p "$HOME_DIR"
            # Earlier bootstraps staged the agent's config into root's home.
            for item in .claude .claude.json .codex .gemini .config .mcp.json; do
              [ -e "/root/$item" ] && cp -a "/root/$item" "$HOME_DIR/" 2>/dev/null
            done
            # State links are re-pointed rather than listed by name: a custom
            # agent may keep state under any dotfile, and the hardcoded list
            # above cannot know it. -f so a stale copy of the same name from
            # the list above is replaced by the link, which is the live one.
            for link in /root/. /root/..* /root/.[!.]* /root/*; do
              [ -L "$link" ] || continue
              case "$(readlink "$link")" in
                /sandbox-state/*)
                  ln -sfn "$(readlink "$link")" "$HOME_DIR/${link##*/}" 2>/dev/null || true
                  ;;
              esac
            done
            chown -R "$TARGET_UID" "$HOME_DIR" 2>/dev/null || true
            \(workspaceOwnership)
            # Installing packages is a normal thing for an agent to do, and it
            # cannot as an unprivileged user. This is still a VM whose egress is
            # enforced outside it, so root here buys the agent nothing beyond
            # its own sandbox.
            if command -v sudo >/dev/null 2>&1; then
              mkdir -p /etc/sudoers.d
              echo "$RUN_AS ALL=(ALL) NOPASSWD: ALL" >/etc/sudoers.d/sandbox 2>/dev/null || true
              chmod 0440 /etc/sudoers.d/sandbox 2>/dev/null || true
            fi
            export HOME="$HOME_DIR"
            export USER="$RUN_AS"
            # setpriv wants numeric ids, not names. Probed by running it, not
            # by its presence: busybox ships a setpriv with none of these
            # options, so an alpine-based agent found it, failed on the flags,
            # and never ran at all.
            if command -v setpriv >/dev/null 2>&1 \
              && setpriv --reuid="$TARGET_UID" --regid="$TARGET_GID" \
                --init-groups --inh-caps=-all true 2>/dev/null; then
              exec setpriv --reuid="$TARGET_UID" --regid="$TARGET_GID" \
                --init-groups --inh-caps=-all "$@"
            elif command -v su-exec >/dev/null 2>&1; then
              exec su-exec "$TARGET_UID" "$@"
            elif command -v runuser >/dev/null 2>&1; then
              exec runuser -u "$RUN_AS" -- "$@"
            else
              exec su -s /bin/sh -c 'exec "$0" "$@"' "$RUN_AS" -- "$@"
            fi
            """
        return ["/bin/sh", "-c", script, "sandbox"] + command
    }

    static let cloneSourceDirectory = "/sandbox-source"

    /// Where the agent's persistent state home is mounted in the guest.
    static let guestStateDirectory = "/sandbox-state"

    /// Point each declared destination at its item in the mounted state home,
    /// then exec.
    ///
    /// Symlinks rather than copies, which is the entire point: the previous
    /// design copied ~/.claude -- 700 MB, 14k files -- through virtiofs into
    /// the guest at every start, 45 seconds before the agent ran anything,
    /// and threw the result away at exit. A symlink into the share is
    /// instant, and writes through it land in the state home and persist.
    ///
    /// Runs as root, before the privilege drop. The drop's own copy step then
    /// finds symlinks at /root/.claude and friends and copies the links, not
    /// the trees behind them.
    static func stateBootstrap(
        wrapping command: [String], links: [(destination: String, target: String)]
    ) -> [String] {
        guard !command.isEmpty, !links.isEmpty else { return command }
        let script =
            links.map { link in
                let destination = shellQuote(link.destination)
                let parent = shellQuote((link.destination as NSString).deletingLastPathComponent)
                let target = shellQuote(link.target)
                // -n so a destination that exists as a directory (an image that
                // ships its own /root/.claude) is replaced, not descended into.
                return """
                    mkdir -p \(parent)
                    rm -rf \(destination)
                    ln -sn \(target) \(destination)
                    """
            }.joined(separator: "\n") + "\nexec \"$@\""
        return ["/bin/sh", "-c", script, "sandbox"] + command
    }

    /// Clone the read-only source into a writable workspace, then exec.
    ///
    /// `--local` would hardlink into the read-only share, so the clone is made
    /// with `file://` to force a real copy. A repository with no commits yet
    /// cannot be cloned, so that falls back to copying the tree.
    static func cloneBootstrap(wrapping command: [String], destination: String) -> [String] {
        guard !command.isEmpty else { return command }
        let script = """
            set -e
            if [ ! -d "\(destination)/.git" ]; then
              mkdir -p "\(destination)"
              if git -C \(cloneSourceDirectory) rev-parse HEAD >/dev/null 2>&1; then
                git clone --quiet "file://\(cloneSourceDirectory)" "\(destination)"
                git -C "\(destination)" remote set-url origin \
                  "$(git -C \(cloneSourceDirectory) remote get-url origin 2>/dev/null \
                     || echo file://\(cloneSourceDirectory))"
              else
                echo "sandbox: no commits to clone; copying the tree instead" >&2
                cp -a \(cloneSourceDirectory)/. "\(destination)/" 2>/dev/null || true
              fi
            fi
            cd "\(destination)"
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "sandbox"] + command
    }

    /// Keep `/workspace` meaning something now that agents see their
    /// workspace at its host path, then exec.
    static func workspaceCompatBootstrap(
        wrapping command: [String], destination: String
    ) -> [String] {
        guard !command.isEmpty else { return command }
        let script = """
            if [ ! -e /workspace ]; then
              MSG=$(ln -sn \(shellQuote(destination)) /workspace 2>&1) \
                || echo "sandbox: /workspace compat link failed: $MSG (uid=$(id -u) pwd=$(pwd) root=$(stat -c %a / 2>/dev/null))" >&2
            fi
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "sandbox"] + command
    }

    static let guestCertificateDirectory = "/etc/sandbox"
    static let guestCertificatePath = "/etc/sandbox/sandbox-ca.crt"

    /// Variables for runtimes that consult their own trust store rather than
    /// the system bundle. Node in particular ignores the bundle entirely.
    static let trustEnvironment: [String: String] = [
        "NODE_EXTRA_CA_CERTS": guestCertificatePath,
        "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
        "CURL_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
        "GIT_SSL_CAINFO": "/etc/ssl/certs/ca-certificates.crt",
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
    ]

    /// Wrap the guest command so the sandbox's own hostname resolves locally.
    ///
    /// The guest is given a generated hostname that exists in no zone, and the
    /// gateway is its only resolver, so resolving it goes out to the gateway
    /// and is refused -- after the libc resolver has spent its full timeout
    /// retrying. Measured at 10s per lookup, and an unreasonable amount of
    /// ordinary software resolves its own hostname on startup: sudo does it on
    /// every invocation, and Python's HTTPServer does it between bind() and
    /// listen(), so `python3 -m http.server` sat there with a bound socket
    /// refusing connections until it completed.
    static func hostnameBootstrap(wrapping command: [String]) -> [String] {
        guard !command.isEmpty else { return command }
        let script = """
            HOST=$(hostname 2>/dev/null)
            # Tested rather than attempted: a failing redirection is reported by
            # the shell itself, so 2>/dev/null on the command does not suppress
            # it, and the guest's first line of output became a permission error
            # about a file the user never asked us to touch.
            if [ -n "$HOST" ] && [ -w /etc/hosts ] \
              && ! grep -qw "$HOST" /etc/hosts 2>/dev/null; then
              echo "127.0.0.1 $HOST" >>/etc/hosts 2>/dev/null || true
            fi
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "sandbox"] + command
    }

    /// Quote a string so a POSIX shell reads it as one literal word.
    ///
    /// Kit content is arbitrary -- launcher scripts, JSON, shell one-liners --
    /// so anything interpolated into a generated script has to be quoted, or a
    /// quote in a kit becomes command injection into the guest's own bootstrap.
    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Wrap the guest command so declared files exist before it runs.
    ///
    /// Content travels base64-encoded. It is arbitrary text -- quotes,
    /// newlines, `$`, backticks -- and base64's alphabet cannot terminate the
    /// quoting or be re-read by the shell, which no amount of escaping the raw
    /// bytes would guarantee.
    static func filesBootstrap(wrapping command: [String], files: [GuestFile]) -> [String] {
        guard !command.isEmpty, !files.isEmpty else { return command }

        var lines: [String] = []
        for file in files {
            let path = shellQuote(file.path)
            let encoded = Data(file.content.utf8).base64EncodedString()
            lines.append("mkdir -p \"$(dirname \(path))\" 2>/dev/null || true")
            // Written to a temporary neighbour and moved into place, so a
            // consumer never sees a half-written file.
            lines.append("printf %s \(shellQuote(encoded)) | base64 -d > \(path).sandbox-part")
            if let mode = file.mode, !mode.isEmpty {
                lines.append("chmod \(shellQuote(mode)) \(path).sandbox-part 2>/dev/null || true")
            }
            lines.append("mv -f \(path).sandbox-part \(path)")
        }
        lines.append("exec \"$@\"")
        return ["/bin/sh", "-c", lines.joined(separator: "\n"), "sandbox"] + command
    }

    /// Wrap the guest command so startup commands run first, as root.
    ///
    /// A failing startup command does not stop the sandbox. These reconcile
    /// state and start helpers; refusing to launch the agent because a helper
    /// declined would make a sandbox less useful than one without the kit.
    /// The failure is reported so it is not silent.
    static func startupBootstrap(wrapping command: [String], startup: [StartupCommand])
        -> [String]
    {
        let runnable = startup.filter { !$0.argv.isEmpty }
        guard !command.isEmpty, !runnable.isEmpty else { return command }

        var lines: [String] = []
        for (index, step) in runnable.enumerated() {
            let quoted = step.argv.map(shellQuote).joined(separator: " ")
            if step.background {
                // A daemon's output would otherwise interleave with the
                // agent's, so it goes to a log the user can read afterwards.
                let log = "/tmp/sandbox-startup-\(index).log"
                lines.append("\(quoted) >\(log) 2>&1 &")
            } else {
                lines.append(
                    "\(quoted) || echo \"sandbox: startup command failed: "
                        + "\(step.argv[0])\" >&2")
            }
        }
        lines.append("exec \"$@\"")
        return ["/bin/sh", "-c", lines.joined(separator: "\n"), "sandbox"] + command
    }

    /// Wrap the guest command so the CA is appended to the system bundle before
    /// it runs.
    ///
    /// Appending rather than replacing: pointing the bundle at our CA alone
    /// would stop every other certificate on the internet from verifying.
    static func trustBootstrap(wrapping command: [String]) -> [String] {
        guard !command.isEmpty else { return command }
        let script = """
            if [ -f \(guestCertificatePath) ]; then
              for bundle in /etc/ssl/certs/ca-certificates.crt \
                            /etc/pki/tls/certs/ca-bundle.crt; do
                [ -f "$bundle" ] && cat \(guestCertificatePath) >> "$bundle" 2>/dev/null
              done
            fi
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "sandbox"] + command
    }
}
