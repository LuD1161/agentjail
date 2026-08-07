#!/usr/bin/env bash
# Hermetic acceptance test for session SSH bootstrap and Git transport.
set -u

PATH="$PATH:/usr/sbin:/usr/bin:/bin"
export PATH

name="ssh-git-e2e.sh"

skip() {
	echo "SKIP: $name: $1"
	exit 0
}

fail() {
	echo "FAIL: $name: $1"
	exit 1
}

if [ "${AGENTJAIL_SSH_GIT_E2E:-}" != "1" ]; then
	skip "set AGENTJAIL_SSH_GIT_E2E=1 to run"
fi

for bin in go git ssh sshd ssh-agent ssh-add ssh-keygen script socat; do
	command -v "$bin" >/dev/null 2>&1 || skip "required binary '$bin' not found"
done

repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
workdir="$(mktemp -d "$repo_root/.agentjail-ssh-git.XXXXXX")"
chmod 700 "$workdir"
daemon_pid=""
sshd_pid=""

cleanup() {
	for pid in "$sshd_pid" "$daemon_pid"; do
		if [ -n "$pid" ]; then
			kill "$pid" >/dev/null 2>&1 || true
			wait "$pid" 2>/dev/null || true
		fi
	done
	rm -rf "$workdir"
}
trap cleanup EXIT

aj="$workdir/agentjail"
shield="$workdir/agentjail-shield"
home="$workdir/home"
project="$workdir/project"
mkdir -p "$home/.agentjail/bin" "$home/.ssh" "$project"

(cd "$repo_root" && go build -o "$aj" ./cmd/agentjail) || fail "build agentjail"
(cd "$repo_root" && go build -o "$shield" ./cmd/agentjail-shield) || fail "build shield"
ln -s "$shield" "$home/.agentjail/bin/agentjail-shield"
ln -s "$aj" "$home/.agentjail/bin/agentjail"
ssh-keygen -q -t ed25519 -N '' -f "$home/.ssh/id_ed25519" || fail "generate disposable client key"
ssh-keygen -q -t rsa -b 2048 -N '' -f "$home/.ssh/id_rsa" || fail "generate configured client key"
cat >"$home/.ssh/config" <<'EOF'
Host github-work
    HostName github.com
    User git
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_rsa
EOF
chmod 600 "$home/.ssh/config"
ssh-keygen -lf "$home/.ssh/id_rsa.pub" | awk '{print $2}' >"$project/expected-fingerprint"
git init -q -b main "$project" || fail "initialize phase-one project"
git -C "$project" remote add origin git@github-work:company/repository.git
HOME="$home" "$aj" install --with-path-shim >/dev/null || fail "install PATH shim"

# Phase 1 uses the public CLI, real shield, and a dummy daemon accept socket.
socat "UNIX-LISTEN:$home/.agentjail/daemon.sock,fork" EXEC:/bin/true &
daemon_pid=$!

agent="$project/codex"
cat >"$agent" <<'EOF'
#!/bin/sh
set -eu
test "${AGENTJAIL_SSH_AGENT_DELEGATED:-}" = "1"
ssh-add -l | awk '{print $2}' > loaded-fingerprints
test "$(wc -l < loaded-fingerprints)" -eq 1
cmp -s loaded-fingerprints expected-fingerprint
printf '%s\n' "$SSH_AUTH_SOCK" > observed-socket
if head -c 1 "$HOME/.ssh/id_ed25519" >/dev/null 2>&1; then
	echo "private key readable inside shield" >&2
	exit 1
fi
if head -c 1 "$HOME/.ssh/id_rsa" >/dev/null 2>&1; then
	echo "configured private key readable inside shield" >&2
	exit 1
fi
EOF
chmod 755 "$agent"

phase1_log="$workdir/phase1.log"
phase1_cmd="cd '$project' && env -u SSH_AUTH_SOCK -u SSH_AGENT_PID HOME='$home' PATH='$home/.agentjail/bin:$project:/usr/sbin:/usr/bin:/bin' codex resume"
if ! printf '\n' | script -qefc "$phase1_cmd" /dev/null >"$phase1_log" 2>&1; then
	sed -n '1,200p' "$phase1_log"
	fail "guided shield launch"
fi
grep -q "session-only OpenSSH" "$phase1_log" || fail "missing OpenSSH ownership notice"
grep -q "SSH agent delegated" "$phase1_log" || fail "missing delegation warning"
grep -q "AgentJail never reads keys/passphrases" "$phase1_log" || fail "missing passphrase privacy notice"
if ! grep -q "Multiple SSH identities match github-work" "$phase1_log"; then
	sed -n '1,200p' "$phase1_log"
	fail "missing configured identity chooser"
fi
observed_socket="$(cat "$project/observed-socket")"
for _ in $(seq 1 20); do
	if ! SSH_AUTH_SOCK="$observed_socket" ssh-add -l >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done
if SSH_AUTH_SOCK="$observed_socket" ssh-add -l >/dev/null 2>&1; then
	fail "session SSH agent still answers after the coding session"
fi
echo "OK: guided setup delegated a session agent while the shield blocked the private key"

# Phase 2 proves real clone, push, and pull through that same native bootstrap.
host_key="$workdir/host-key"
authorized_keys="$workdir/authorized_keys"
sshd_config="$workdir/sshd_config"
sshd_log="$workdir/sshd.log"
remote="$workdir/remote.git"
seed="$workdir/seed"
port=$(( (RANDOM % 20000) + 20000 ))

ssh-keygen -q -t ed25519 -N '' -f "$host_key" || fail "generate disposable host key"
cp "$home/.ssh/id_ed25519.pub" "$authorized_keys"
chmod 600 "$authorized_keys"
git init -q -b main "$seed" || fail "initialize seed repository"
git -C "$seed" config user.name "AgentJail E2E"
git -C "$seed" config user.email "e2e@invalid"
printf 'seed\n' >"$seed/history.txt"
git -C "$seed" add history.txt
git -C "$seed" commit -qm seed
seed_commit="$(git -C "$seed" rev-parse HEAD)"
printf 'push-a\n' >>"$seed/history.txt"
git -C "$seed" commit -qam push-a
git -C "$seed" tag next
printf 'push-b\n' >>"$seed/history.txt"
git -C "$seed" commit -qam push-b
git -C "$seed" tag later
git -C "$seed" reset -q --hard "$seed_commit"
git clone -q --bare "$seed" "$remote" || fail "initialize bare repository"
git --git-dir="$remote" symbolic-ref HEAD refs/heads/main

cat >"$sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $host_key
AuthorizedKeysFile $authorized_keys
PidFile $workdir/sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
PermitRootLogin no
LogLevel ERROR
Subsystem sftp /bin/false
EOF

sshd_bin="$(command -v sshd)"
"$sshd_bin" -D -f "$sshd_config" -E "$sshd_log" &
sshd_pid=$!
for _ in $(seq 1 50); do
	if ! kill -0 "$sshd_pid" 2>/dev/null; then
		fail "local sshd exited"
	fi
	if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
		exec 3<&- 3>&-
		break
	fi
	sleep 0.1
done

git_child="$workdir/git-child"
cat >"$git_child" <<EOF
#!/bin/sh
set -eu
cd '$workdir'
export GIT_SSH_COMMAND="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent=\$SSH_AUTH_SOCK"
remote_url='ssh://$(id -un)@127.0.0.1:$port$remote'
git clone -q "\$remote_url" clone-a
git -C clone-a push -q origin refs/tags/next:refs/heads/main
git clone -q "\$remote_url" clone-b
git -C clone-b push -q origin refs/tags/later:refs/heads/main
git -C clone-a pull -q --ff-only
grep -q '^push-b\$' clone-a/history.txt
printf '%s\n' "\$SSH_AUTH_SOCK" > git-observed-socket
printf '%s\n' "\$SSH_AGENT_PID" > git-observed-pid
EOF
chmod 755 "$git_child"

phase2_log="$workdir/phase2.log"
phase2_cmd="env -u SSH_AUTH_SOCK -u SSH_AGENT_PID HOME='$home' PATH='/usr/sbin:/usr/bin:/bin' ssh-agent '$aj' __ssh-bootstrap --identity '$home/.ssh/id_ed25519' -- '$git_child'"
if ! script -qefc "$phase2_cmd" /dev/null >"$phase2_log" 2>&1; then
	sed -n '1,200p' "$phase2_log"
	fail "Git clone/push/pull through session agent"
fi
git_socket="$(cat "$workdir/git-observed-socket")"
git_agent_pid="$(cat "$workdir/git-observed-pid")"
for _ in $(seq 1 20); do
	if ! SSH_AUTH_SOCK="$git_socket" ssh-add -l >/dev/null 2>&1 && ! kill -0 "$git_agent_pid" >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done
if SSH_AUTH_SOCK="$git_socket" ssh-add -l >/dev/null 2>&1 || kill -0 "$git_agent_pid" >/dev/null 2>&1; then
	fail "Git session SSH agent survived its command"
fi
grep -q '^push-b$' "$workdir/clone-a/history.txt" || fail "pull did not receive second push"
echo "PASS: $name: guided shield delegation and real Git clone/push/pull"
