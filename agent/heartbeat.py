"""OGK-Agent — vòng lặp heartbeat (xem mục 5.2 trong Design.md).

Bản dev: chạy tay, chưa phải một phần của Windows Service. Dùng để kiểm
tra tính năng Heartbeat hoạt động đúng giữa Windows thật và VM thật.

Chạy 1 lần rồi thoát (để test nhanh):
    python heartbeat.py --server 10.11.0.55 --ca-cert certs\\ogk-ca.crt --once

Chạy lặp mỗi 60 giây (giống hành vi thật của agent sau này):
    python heartbeat.py --server 10.11.0.55 --ca-cert certs\\ogk-ca.crt
"""
from __future__ import annotations

import argparse
import json
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


def load_state(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(
            f"Không tìm thấy {path} — chạy enroll.py trước để ghép đôi thiết bị."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def _request(url: str, ca_cert: str, access_token: str, method: str = "GET", body: bytes | None = None):
    ctx = ssl.create_default_context(cafile=ca_cert)
    headers = {"Authorization": f"Bearer {access_token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Server từ chối ({exc.code}) tại {url}: {detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"Không kết nối được tới {url}: {exc.reason}")


def send_heartbeat(server: str, port: int, ca_cert: str, access_token: str, policy_version: int) -> dict:
    url = f"https://{server}:{port}/heartbeat"
    body = json.dumps(
        {
            # Bản dev: chưa đếm thời gian sử dụng thật (chưa có Policy
            # Enforcer) — gửi 0, sẽ nối số liệu thật khi làm tính năng đó.
            "policy_version": policy_version,
            "quota_used_seconds": 0,
            "queued_event_count": 0,
        }
    ).encode("utf-8")
    return _request(url, ca_cert, access_token, method="POST", body=body)


def fetch_policy(server: str, port: int, ca_cert: str, access_token: str) -> dict:
    url = f"https://{server}:{port}/policy"
    return _request(url, ca_cert, access_token, method="GET")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument("--state", default="agent_state/device_token.json")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--once", action="store_true", help="Gửi 1 lần rồi thoát, không lặp")
    args = parser.parse_args()

    state_path = Path(args.state)
    state = load_state(state_path)
    policy_version = state.get("policy_version", 0)
    access_token = state["access_token"]

    print(f"Bắt đầu heartbeat tới {args.server}:{args.port} (device_id={state['device_id']})")
    print(f"Chu kỳ: {'1 lần duy nhất' if args.once else f'mỗi {args.interval}s'}")
    print()

    while True:
        ts = datetime.now().strftime("%H:%M:%S")
        result = send_heartbeat(args.server, args.port, args.ca_cert, access_token, policy_version)
        print(
            f"[{ts}] heartbeat OK — server: policy_version={result['policy_version']} "
            f"(agent đang có v{policy_version}), policy_changed={result['policy_changed']}"
        )

        if result["policy_changed"]:
            print("  -> Policy đổi, gọi GET /policy ...")
            policy = fetch_policy(args.server, args.port, args.ca_cert, access_token)
            print(f"  -> Nhận policy v{policy['version']}: quota={policy['quota']}")
            policy_version = policy["version"]
            state["policy_version"] = policy_version
            save_state(state_path, state)

        if result["pending_commands"]:
            for cmd in result["pending_commands"]:
                print(f"  -> LỆNH MỚI: {cmd['type']} (id={cmd['command_id']}) payload={cmd['payload']}")
                # TODO (tính năng Windows Service): thực thi lệnh thật ở đây
                # (vd grant_minutes -> cộng thêm quota cục bộ).

        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
