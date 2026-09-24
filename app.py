"""网络侵害事件受理与协同处置的业务核心。

设计要点：
- 所有事实以不可变事件落账（见 store.py），删除、改名、补充、撤回只追加记录；
- 普通批评只登记线索、不立事件；直接人身威胁自动按值班规则升级且只通知一次；
- 聚类只产生合并建议，须保护专员人工确认；
- 报案/平台投诉/公开澄清按职责分离提交、分角色复核，禁止自复核；
- 平台回调按 callback_id 幂等，重复回调不通知、不产生第二案件；
- 申诉期间限制敏感材料扩散并阻断对外动作；授权撤回不抹除责任链。
"""

import hashlib
import json
from datetime import datetime, timezone, timedelta

from domain import load_config
from store import EventStore, new_id

CST = timezone(timedelta(hours=8))

# 仅供联调的威胁线索提示词：最终等级仍以提交人填报、保护专员确认为准
_THREAT_HINTS = ("弄死", "杀死", "砍死", "打死", "别想走", "等着", "上门", "堵你", "炸死", "废了你")
_CRITICISM_HINTS = ("发挥", "状态", "战术", "换人", "表现", "踢得", "输球")


def now_iso():
    return datetime.now(CST).isoformat(timespec="seconds")


def content_hash(raw_excerpt):
    return hashlib.sha256((raw_excerpt or "").encode("utf-8")).hexdigest()


def suggest_severity(text):
    """联调用启发式：根据文本给严重度建议，不替代人工判定。"""
    if not text:
        return None
    if any(hint in text for hint in _THREAT_HINTS):
        return "direct_threat"
    if any(hint in text for hint in _CRITICISM_HINTS):
        return "criticism"
    return "abuse"


class AppError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _require(actor, allowed_roles):
    if not actor or "role" not in actor:
        raise AppError("缺少操作人信息 actor(name, role)")
    if actor["role"] not in allowed_roles:
        raise AppError(f"角色 {actor['role']} 无权执行该操作，允许角色：{'、'.join(allowed_roles)}", 403)


class SafeguardingApp:
    SUBMIT_ROLES = ("当事人代理", "俱乐部保护专员")

    def __init__(self, config=None, store_path=None):
        self.config = config or load_config()
        self.store = EventStore(store_path)
        self.reports = {}            # report_no -> 线索记录
        self.incidents = {}          # incident_id -> 事件投影
        self.actions = {}            # action_id -> 动作记录
        self.suggestions = {}        # suggestion_id -> 合并建议
        self.callbacks = {}          # callback_id -> 首次处理结果
        self.notifications = []      # 通知外发箱（抽象渠道）
        self.preservation_orders = {}  # order_id -> 保全令投影
        self.manifests = {}          # manifest_id -> 材料清单投影
        self.conflicts = {}          # conflict_id -> 移交冲突复核
        self._handoff_keys = {}      # (incident_id, 接收机构, 用途) -> 最新保全令
        self._suggestion_keys = set()
        self._replay()
        self.store.subscribe(self._apply)

    # ------------------------------------------------------------------ 重放
    def _replay(self):
        for event in self.store.replay():
            self._apply(event)

    def _append(self, event_type, payload, event_id=None):
        event, _duplicate = self.store.append(event_type, payload, event_id=event_id)
        return event

    def _apply(self, event):
        handler = getattr(self, f"_on_{event['type']}", None)
        if handler:
            handler(event["payload"])

    # ---------------------------------------------------------- 线索报送/立案
    def submit_report(self, payload, actor):
        _require(actor, self.SUBMIT_ROLES)
        severity = payload.get("severity")
        if not self.config.is_valid_severity(severity):
            raise AppError(f"未知严重度：{severity}")
        platform = payload.get("platform")
        if platform and platform not in self.config.platforms:
            raise AppError(f"未知平台：{platform}")
        if not payload.get("content_url"):
            raise AppError("线索必须包含受控引用 content_url")
        victim = payload.get("victim_code")
        if not victim:
            raise AppError("线索必须包含受侵害当事人 victim_code")

        report_no = new_id("rpt")
        raw = payload.get("raw_excerpt") or ""
        sha = content_hash(raw)
        scopes = payload.get("授权范围")
        if scopes is None:
            scopes = self.config.default_scopes
        unknown_scopes = set(scopes) - set(self.config.scopes)
        if unknown_scopes:
            raise AppError(f"未知授权范围：{sorted(unknown_scopes)}")

        report = {
            "report_no": report_no,
            "submitted_by": actor.get("name"),
            "submitter_role": actor["role"],
            "victim_code": victim,
            "platform": platform,
            "content_url": payload["content_url"],
            "content_sha256": sha,
            "severity": severity,
            "linked_accounts": payload.get("linked_accounts", []),
            "receipts": payload.get("receipts", []),
            "received_at": now_iso(),
            "decision": None,
            "incident_id": None,
        }
        self._append("report_received", {
            "report_no": report_no,
            "submitted_by": actor.get("name"),
            "submitter_role": actor["role"],
            "victim_code": victim,
            "platform": platform,
            "content_url": payload["content_url"],
            "content_sha256": sha,
            "severity": severity,
            "linked_accounts": payload.get("linked_accounts", []),
            "received_at": report["received_at"],
        })
        self.reports[report_no] = report

        # 普通批评：只登记观察，不立为保护事件，避免把批评误当网暴进入处置流程
        if not self.config.is_openable_severity(severity):
            report["decision"] = "不立案：普通批评，登记观察"
            self._append("report_screened", {
                "report_no": report_no, "decision": report["decision"], "at": now_iso(),
            })
            return {"report_no": report_no, "incident_id": None, "decision": report["decision"]}

        incident_id = self._open_incident(report, scopes)
        report["incident_id"] = incident_id
        return {"report_no": report_no, "incident_id": incident_id, "decision": "已立案"}

    def _open_incident(self, report, scopes):
        incident_id = new_id("inc")
        at = now_iso()
        self._append("incident_opened", {
            "incident_id": incident_id,
            "report_no": report["report_no"],
            "victim_code": report["victim_code"],
            "platform": report["platform"],
            "severity": report["severity"],
            "opened_at": at,
        })
        self._append("consent_granted", {
            "incident_id": incident_id, "scopes": scopes,
            "by": report["submitted_by"], "at": at,
        })
        self._append("evidence_registered", {
            "incident_id": incident_id,
            "evidence_id": new_id("ev"),
            "kind": "url",
            "content_ref": report["content_url"],
            "content_sha256": report["content_sha256"],
            "state": "online",
            "submitted_by": report["submitted_by"],
            "at": at,
            "note": "立案线索的受控引用",
        })
        for account in report["linked_accounts"]:
            self._append("account_linked", {
                "incident_id": incident_id,
                "link_id": new_id("acct"),
                "platform": account.get("platform"),
                "account_key": account.get("account_key"),
                "url": account.get("url"),
                "display_name": account.get("display_name"),
                "at": at,
            })
        for receipt in report["receipts"]:
            self._append("receipt_recorded", {
                "incident_id": incident_id,
                "receipt_id": receipt.get("receipt_id"),
                "platform": receipt.get("platform", report["platform"]),
                "status": receipt.get("status"),
                "reported_at": receipt.get("reported_at"),
                "via": "report",
                "at": now_iso(),
            })

        incident = self.incidents[incident_id]
        if self.config.should_escalate(report["severity"]):
            self._raise_escalation(incident_id, "立案等级为直接人身威胁，按值班规则自动升级")
        self._suggest_clusters_for(incident)
        return incident_id

    # ------------------------------------------------------------- 事件投影
    def _on_report_received(self, p):
        # submit_report 直接持有 report 对象；重放时重建
        if p["report_no"] not in self.reports:
            self.reports[p["report_no"]] = {
                "report_no": p["report_no"], "submitted_by": p["submitted_by"],
                "submitter_role": p["submitter_role"], "victim_code": p["victim_code"],
                "platform": p["platform"], "content_url": p["content_url"],
                "content_sha256": p["content_sha256"], "severity": p["severity"],
                "linked_accounts": p.get("linked_accounts", []), "receipts": [],
                "received_at": p["received_at"], "decision": None, "incident_id": None,
            }

    def _on_report_screened(self, p):
        report = self.reports.get(p["report_no"])
        if report:
            report["decision"] = p["decision"]

    def _on_incident_opened(self, p):
        self.incidents[p["incident_id"]] = {
            "incident_id": p["incident_id"],
            "report_nos": [p["report_no"]],
            "victim_code": p["victim_code"],
            "platform": p["platform"],
            "severity": p["severity"],
            "opened_at": p["opened_at"],
            "closed_at": None,
            "close_reason": None,
            "consent_scopes": [],
            "evidence": [],
            "accounts": [],
            "receipts": [],
            "actions": [],
            "escalation": None,
            "appeal": None,
            "merged_into": None,
            "absorbed": [],
            "false_report_upheld": False,
        }
        report = self.reports.get(p["report_no"])
        if report is not None and report.get("incident_id") is None:
            report["incident_id"] = p["incident_id"]
            report["decision"] = "已立案"

    def _on_consent_granted(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            for scope in p["scopes"]:
                if scope not in inc["consent_scopes"]:
                    inc["consent_scopes"].append(scope)

    def _on_consent_revoked(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["consent_scopes"] = [s for s in inc["consent_scopes"] if s not in p["scopes"]]

    def _on_evidence_registered(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["evidence"].append({
                "evidence_id": p["evidence_id"], "kind": p["kind"],
                "content_ref": p["content_ref"], "content_sha256": p["content_sha256"],
                "state": p.get("state", "online"), "submitted_by": p.get("submitted_by"),
                "at": p["at"], "note": p.get("note", ""),
            })

    def _on_evidence_supplemented(self, p):
        self._on_evidence_registered(p)

    def _on_content_state_changed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            for ev in inc["evidence"]:
                if ev["evidence_id"] == p["evidence_id"]:
                    ev["state"] = p["new_state"]

    def _on_account_linked(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["accounts"].append({
                "link_id": p["link_id"], "platform": p["platform"],
                "account_key": p["account_key"], "url": p.get("url"),
                "display_name": p.get("display_name"),
                "name_history": ([{"name": p.get("display_name"), "at": p["at"]}]
                                 if p.get("display_name") else []),
            })

    def _on_account_renamed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            for acct in inc["accounts"]:
                if acct["platform"] == p["platform"] and acct["account_key"] == p["account_key"]:
                    acct["name_history"].append({"name": p["new_name"], "at": p["at"]})
                    acct["display_name"] = p["new_name"]

    def _on_receipt_recorded(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["receipts"] = [r for r in inc["receipts"] if r["receipt_id"] != p["receipt_id"]]
            inc["receipts"].append({
                "receipt_id": p["receipt_id"], "platform": p["platform"],
                "status": p["status"], "reported_at": p.get("reported_at"),
                "via": p.get("via", "callback"), "at": p["at"],
            })

    def _on_escalation_raised(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["escalation"] = {
                "escalation_id": p["escalation_id"], "reason": p["reason"],
                "raised_at": p["at"], "status": "open",
                "last_confirmed_at": p["at"], "acknowledged_at": None,
                "acknowledged_by": None,
            }

    def _on_escalation_confirmed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc and inc["escalation"]:
            inc["escalation"]["last_confirmed_at"] = p["at"]

    def _on_escalation_acknowledged(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc and inc["escalation"]:
            inc["escalation"]["status"] = "acknowledged"
            inc["escalation"]["acknowledged_at"] = p["at"]
            inc["escalation"]["acknowledged_by"] = p["by"]

    def _on_severity_confirmed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["severity"] = p["severity"]

    def _on_merge_suggested(self, p):
        sugg = {
            "suggestion_id": p["suggestion_id"], "incident_ids": list(p["incident_ids"]),
            "reason": p["reason"], "status": "open",
            "created_at": p["created_at"], "resolved_by": None, "resolved_at": None,
            "merged_into": None,
        }
        self.suggestions[p["suggestion_id"]] = sugg
        self._suggestion_keys.add(self._pair_key(p["incident_ids"]))

    def _on_suggestion_resolved(self, p):
        sugg = self.suggestions.get(p["suggestion_id"])
        if sugg:
            sugg["status"] = p["decision"]
            sugg["resolved_by"] = p["by"]
            sugg["resolved_at"] = p["at"]
            sugg["merged_into"] = p.get("merged_into")

    def _on_incidents_merged(self, p):
        survivor = self.incidents.get(p["survivor_id"])
        absorbed = self.incidents.get(p["merged_id"])
        if survivor and absorbed:
            survivor["absorbed"].append(p["merged_id"])
            absorbed["merged_into"] = p["survivor_id"]

    def _on_appeal_opened(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["appeal"] = {"reason": p["reason"], "opened_by": p["by"],
                             "opened_at": p["at"], "status": "open",
                             "resolved_at": None, "decision": None}

    def _on_appeal_resolved(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc and inc["appeal"]:
            inc["appeal"]["status"] = "resolved"
            inc["appeal"]["decision"] = p["decision"]
            inc["appeal"]["resolved_at"] = p["at"]
            if p["decision"] == "upheld":
                inc["false_report_upheld"] = True

    def _on_incident_closed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["closed_at"] = p["at"]
            inc["close_reason"] = p["reason"]

    def _on_action_proposed(self, p):
        self.actions[p["action_id"]] = {
            "action_id": p["action_id"], "incident_id": p["incident_id"],
            "action_type": p["action_type"], "params": p.get("params", {}),
            "proposed_by": p["proposed_by"], "proposed_by_role": p["proposed_by_role"],
            "required_reviewer_role": p["required_reviewer_role"],
            "required_scopes": p.get("required_scopes", []),
            "status": "pending", "reviewer": None, "reviewer_role": None,
            "review_reason": None, "reviewed_at": None,
            "executed_at": None, "result": None, "proposed_at": p["at"],
        }
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["actions"].append(p["action_id"])

    def _on_action_reviewed(self, p):
        action = self.actions.get(p["action_id"])
        if action:
            action["status"] = "approved" if p["decision"] == "approve" else "rejected"
            action["reviewer"] = p["reviewer"]
            action["reviewer_role"] = p["reviewer_role"]
            action["review_reason"] = p.get("reason")
            action["reviewed_at"] = p["at"]

    def _on_action_executed(self, p):
        action = self.actions.get(p["action_id"])
        if action:
            action["status"] = "executed"
            action["executed_at"] = p["at"]
            action["result"] = p.get("result", {})
            if p.get("receipt"):
                inc = self.incidents.get(action["incident_id"])
                if inc:
                    receipt = p["receipt"]
                    inc["receipts"] = [r for r in inc["receipts"]
                                       if r["receipt_id"] != receipt.get("receipt_id")]
                    inc["receipts"].append({"via": "action", "at": p["at"], **receipt})

    def _on_notification_sent(self, p):
        self.notifications.append(p)

    def _on_callback_processed(self, p):
        if p["callback_id"] not in self.callbacks:
            self.callbacks[p["callback_id"]] = p["result"]

    # ------------------------------------------------------- 保全移交投影
    def _on_preservation_order_issued(self, p):
        order = {
            "order_id": p["order_id"], "incident_id": p["incident_id"],
            "case_no": p.get("case_no"), "version": p["version"],
            "purpose": p["purpose"], "receiver": p["receiver"],
            "field_scope": list(p["field_scope"]),
            "issued_at": p["issued_at"], "expires_at": p["expires_at"],
            "issued_by": p["issued_by"],
            "basis": p.get("basis", "按案件与用途依法保全"),
            "supersedes": p.get("supersedes"),
            "status": "active",
            "manifest_id": None,
            "expected_receipts": list(p.get("expected_receipts", [])),
            "received_receipts": {},
            "extensions": [],
        }
        self.preservation_orders[p["order_id"]] = order
        self._handoff_keys[self._handoff_key(
            p["incident_id"], p["receiver"].get("org_code"), p["purpose"])] = p["order_id"]

    def _on_preservation_order_superseded(self, p):
        order = self.preservation_orders.get(p["order_id"])
        if order:
            order["status"] = "superseded"
            order["superseded_by"] = p["superseded_by"]

    def _on_preservation_extended(self, p):
        order = self.preservation_orders.get(p["order_id"])
        if order:
            order["extensions"].append({
                "extended_at": p["at"], "previous_expires_at": p["previous_expires_at"],
                "new_expires_at": p["new_expires_at"], "reason": p["reason"],
                "by": p["by"], "judicial": p.get("judicial", False),
            })
            order["expires_at"] = p["new_expires_at"]

    def _on_manifest_generated(self, p):
        manifest = {
            "manifest_id": p["manifest_id"], "order_id": p["order_id"],
            "incident_id": p["incident_id"], "order_version": p["order_version"],
            "generated_at": p["generated_at"], "digest": p["digest"],
            "items": p["items"],
            "surrender_ack": None,
            "receiver_ack": None,
            "status": "pending_ack",
            "events": [],
        }
        self.manifests[p["manifest_id"]] = manifest
        order = self.preservation_orders.get(p["order_id"])
        if order:
            order["manifest_id"] = p["manifest_id"]

    def _on_manifest_acknowledged(self, p):
        manifest = self.manifests.get(p["manifest_id"])
        if manifest:
            ack = {"by": p["by"], "by_role": p["by_role"], "party": p["party"], "at": p["at"],
                   "note": p.get("note")}
            if p["party"] == "surrender":
                manifest["surrender_ack"] = ack
            else:
                manifest["receiver_ack"] = ack
            if manifest["surrender_ack"] and manifest["receiver_ack"]:
                manifest["status"] = "acknowledged"

    def _on_manifest_event_appended(self, p):
        manifest = self.manifests.get(p["manifest_id"])
        if manifest:
            manifest["events"].append({
                "kind": p["kind"], "at": p["at"], "by": p.get("by"),
                "by_role": p.get("by_role"), "detail": p.get("detail", {}),
            })
            if p["kind"] in ("partial_rejection", "returned"):
                manifest["status"] = p["kind"]
            # 补件只作为后续事件追加，先前签认回执与清单状态均不改写

    def _on_handoff_conflict_raised(self, p):
        self.conflicts[p["conflict_id"]] = {
            "conflict_id": p["conflict_id"], "incident_id": p["incident_id"],
            "order_id": p["order_id"], "existing_manifest_id": p["existing_manifest_id"],
            "reason": p["reason"], "differences": p.get("differences", []),
            "raised_at": p["at"], "status": "open",
            "resolved_by": None, "resolved_at": None, "decision": None,
        }

    def _on_handoff_conflict_resolved(self, p):
        conflict = self.conflicts.get(p["conflict_id"])
        if conflict:
            conflict["status"] = "resolved"
            conflict["resolved_by"] = p["by"]
            conflict["resolved_at"] = p["at"]
            conflict["decision"] = p["decision"]
            conflict["note"] = p.get("note")

    # ------------------------------------------------------------- 严重度确认
    def confirm_severity(self, incident_id, severity, actor):
        _require(actor, ("俱乐部保护专员", "俱乐部值班主管"))
        inc = self._get_open_incident(incident_id)
        if not self.config.is_valid_severity(severity):
            raise AppError(f"未知严重度：{severity}")
        self._append("severity_confirmed", {
            "incident_id": incident_id, "severity": severity,
            "by": actor.get("name"), "at": now_iso(),
        })
        if self.config.should_escalate(severity):
            esc = inc["escalation"]
            if esc and esc["status"] == "open":
                # 同一值班周期内重复确认：只刷新确认时间，不再升级、不再次通知
                self._append("escalation_confirmed", {
                    "incident_id": incident_id, "at": now_iso(),
                })
            else:
                self._raise_escalation(incident_id, "等级经确认升至直接人身威胁")

    # ------------------------------------------------------------- 值班升级
    def _raise_escalation(self, incident_id, reason):
        inc = self._get_open_incident(incident_id)
        if inc["escalation"] and inc["escalation"]["status"] == "open":
            return inc["escalation"]["escalation_id"]
        escalation_id = new_id("esc")
        at = now_iso()
        self._append("escalation_raised", {
            "incident_id": incident_id, "escalation_id": escalation_id,
            "reason": reason, "at": at,
        })
        for role in self.config.duty["通知角色"]:
            self._append("notification_sent", {
                "notif_id": new_id("ntf"),
                "incident_id": incident_id,
                "channel": "duty",
                "to_role": role,
                "reason": reason,
                "escalation_id": escalation_id,
                "at": at,
            })
        return escalation_id

    def acknowledge_escalation(self, incident_id, actor):
        _require(actor, ("俱乐部值班主管",))
        inc = self._get_incident(incident_id)
        if not inc["escalation"] or inc["escalation"]["status"] != "open":
            raise AppError("该事件没有待响应的值班升级")
        self._append("escalation_acknowledged", {
            "incident_id": incident_id, "by": actor.get("name"), "at": now_iso(),
        })

    # ------------------------------------------------------------------ 证据
    def add_evidence(self, incident_id, payload, actor):
        _require(actor, self.SUBMIT_ROLES + ("平台联络员", "法务复核员"))
        inc = self._get_open_incident(incident_id)
        self._assert_not_appealed(inc)
        if not payload.get("content_ref"):
            raise AppError("证据补充必须提供受控引用 content_ref，不接受原始内容入库")
        evidence_id = new_id("ev")
        self._append("evidence_registered", {
            "incident_id": incident_id, "evidence_id": evidence_id,
            "kind": payload.get("kind", "supplement"),
            "content_ref": payload["content_ref"],
            "content_sha256": payload.get("content_sha256")
                              or content_hash(payload.get("raw_excerpt", "")),
            "state": payload.get("state", "online"),
            "submitted_by": actor.get("name"), "at": now_iso(),
            "note": payload.get("note", "证据补充"),
        })
        return {"evidence_id": evidence_id}

    def link_account(self, incident_id, payload, actor):
        _require(actor, self.SUBMIT_ROLES + ("平台联络员",))
        inc = self._get_open_incident(incident_id)
        if not payload.get("account_key"):
            raise AppError("关联账号必须包含 platform 与 account_key")
        link_id = new_id("acct")
        self._append("account_linked", {
            "incident_id": incident_id, "link_id": link_id,
            "platform": payload.get("platform"), "account_key": payload["account_key"],
            "url": payload.get("url"), "display_name": payload.get("display_name"),
            "at": now_iso(),
        })
        self._suggest_clusters_for(inc)
        return {"link_id": link_id}

    # ------------------------------------------------------------------ 聚类
    def _pair_key(self, incident_ids):
        return "|".join(sorted(incident_ids))

    def _suggest_clusters_for(self, inc):
        """只生成合并建议；任何合并都必须由保护专员确认。"""
        candidates = []
        for other_id, other in self.incidents.items():
            if other_id == inc["incident_id"] or other.get("merged_into") or other.get("closed_at"):
                continue
            reason = None
            same_victim = other["victim_code"] == inc["victim_code"]
            if same_victim:
                old_hashes = {e["content_sha256"] for e in other["evidence"] if e["content_sha256"]}
                new_hashes = {e["content_sha256"] for e in inc["evidence"] if e["content_sha256"]}
                if old_hashes & new_hashes:
                    reason = "同一当事人且内容哈希一致"
            if reason is None:
                old_keys = {(a["platform"], a["account_key"]) for a in other["accounts"]}
                new_keys = {(a["platform"], a["account_key"]) for a in inc["accounts"]}
                if old_keys & new_keys:
                    reason = "共享同一平台关联账号"
            if reason:
                candidates.append((other_id, reason))
        for other_id, reason in candidates:
            pair = [inc["incident_id"], other_id]
            if self._pair_key(pair) in self._suggestion_keys:
                continue
            self._append("merge_suggested", {
                "suggestion_id": new_id("sug"),
                "incident_ids": pair,
                "reason": reason,
                "created_at": now_iso(),
            })

    def resolve_suggestion(self, suggestion_id, decision, actor, target_incident=None):
        _require(actor, ("俱乐部保护专员",))
        sugg = self.suggestions.get(suggestion_id)
        if not sugg:
            raise AppError("合并建议不存在", 404)
        if sugg["status"] != "open":
            raise AppError("该建议已处理")
        if decision not in ("accept", "reject"):
            raise AppError("decision 仅支持 accept/reject")
        merged_into = None
        if decision == "accept":
            merged_into = target_incident or sugg["incident_ids"][0]
            source_id = sugg["incident_ids"][1] if merged_into == sugg["incident_ids"][0] else sugg["incident_ids"][0]
            if merged_into not in sugg["incident_ids"]:
                raise AppError("合并目标必须是建议涉及的事件之一")
            self._get_open_incident(merged_into)
            self._get_open_incident(source_id)
            self._append("incidents_merged", {
                "survivor_id": merged_into, "merged_id": source_id,
                "by": actor.get("name"), "at": now_iso(),
            })
        self._append("suggestion_resolved", {
            "suggestion_id": suggestion_id, "decision": decision,
            "by": actor.get("name"), "at": now_iso(), "merged_into": merged_into,
        })
        return {"status": decision, "merged_into": merged_into}

    # ------------------------------------------------------------------ 授权
    def grant_consent(self, incident_id, scopes, actor):
        _require(actor, ("当事人代理",))
        self._get_incident(incident_id)
        unknown = set(scopes) - set(self.config.scopes)
        if unknown:
            raise AppError(f"未知授权范围：{sorted(unknown)}")
        self._append("consent_granted", {
            "incident_id": incident_id, "scopes": scopes,
            "by": actor.get("name"), "at": now_iso(),
        })
        return {"scopes": self.incidents[incident_id]["consent_scopes"]}

    def revoke_consent(self, incident_id, scopes, actor):
        _require(actor, ("当事人代理",))
        inc = self._get_incident(incident_id)
        unknown = set(scopes) - set(self.config.scopes)
        if unknown:
            raise AppError(f"未知授权范围：{sorted(unknown)}")
        # 申诉或司法移交存续期间，证据留存授权不可撤回（其余授权仍可撤回）
        if "evidence_storage" in scopes and (inc["appeal"] and inc["appeal"]["status"] == "open"):
            raise AppError("误报申诉存续期间不可撤回证据留存授权")
        if "evidence_storage" in scopes and self._has_executed(incident_id, "police_report"):
            raise AppError("已报案移交的事件处于司法程序中，证据留存授权不可单独撤回")
        if "evidence_storage" in scopes and self._has_active_preservation(incident_id):
            raise AppError("存在尚未到期的依法保全令，最小材料须继续留存，证据留存授权不可单独撤回")
        self._append("consent_revoked", {
            "incident_id": incident_id, "scopes": scopes,
            "by": actor.get("name"), "at": now_iso(),
        })
        return {"scopes": inc["consent_scopes"]}

    def _has_executed(self, incident_id, action_type):
        return any(self.actions[a]["action_type"] == action_type
                   and self.actions[a]["status"] == "executed"
                   for a in self.incidents[incident_id]["actions"])

    # ------------------------------------------------------------------ 动作
    EXTERNAL_ACTIONS = ("platform_complaint", "police_report", "public_statement")

    def propose_action(self, incident_id, action_type, actor, params=None):
        _require(actor, self.SUBMIT_ROLES)
        inc = self._get_open_incident(incident_id)
        if action_type not in self.config.actions:
            raise AppError(f"未知处置动作：{action_type}")
        if action_type in self.EXTERNAL_ACTIONS and inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("误报申诉期间不得发起新的对外动作")
        action_id = new_id("act")
        self._append("action_proposed", {
            "action_id": action_id, "incident_id": incident_id,
            "action_type": action_type, "params": params or {},
            "proposed_by": actor.get("name"), "proposed_by_role": actor["role"],
            "required_reviewer_role": self.config.reviewer_role_for(action_type),
            "required_scopes": self.config.required_scopes_for(action_type),
            "at": now_iso(),
        })
        return {"action_id": action_id,
                "required_reviewer_role": self.config.reviewer_role_for(action_type)}

    def review_action(self, action_id, decision, actor, reason=None):
        action = self.actions.get(action_id)
        if not action:
            raise AppError("处置动作不存在", 404)
        inc = self._get_open_incident(action["incident_id"])
        if action["status"] != "pending":
            raise AppError(f"动作已{action['status']}，不能重复复核")
        if decision not in ("approve", "reject"):
            raise AppError("decision 仅支持 approve/reject")
        if actor["role"] != action["required_reviewer_role"]:
            raise AppError(
                f"该动作须由 {action['required_reviewer_role']} 复核", 403)
        if self.config.separation["禁止自复核"] and actor.get("name") == action["proposed_by"]:
            raise AppError("提交人不能复核自己发起的动作", 403)
        self._append("action_reviewed", {
            "action_id": action_id, "incident_id": action["incident_id"],
            "decision": decision,
            "reviewer": actor.get("name"), "reviewer_role": actor["role"],
            "reason": reason, "at": now_iso(),
        })
        return {"action_id": action_id, "status": "approved" if decision == "approve" else "rejected"}

    def execute_action(self, action_id, actor):
        action = self.actions.get(action_id)
        if not action:
            raise AppError("处置动作不存在", 404)
        inc = self._get_open_incident(action["incident_id"])
        if action["status"] != "approved":
            raise AppError("仅已复核通过的动作可以执行")
        missing = [s for s in action["required_scopes"] if s not in inc["consent_scopes"]]
        if missing:
            names = "、".join(self.config.scopes[s]["名称"] for s in missing)
            raise AppError(f"当事人当前授权不足，缺少：{names}；动作保持已批准待执行", 409)
        if action["action_type"] in self.EXTERNAL_ACTIONS and inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("误报申诉期间不得执行对外动作", 409)

        at = now_iso()
        receipt = None
        result = {"executed_by": actor.get("name")}
        if action["action_type"] == "platform_complaint":
            platform = action["params"].get("platform") or inc["platform"]
            receipt = {
                "receipt_id": new_id("RCP"),
                "platform": platform,
                "status": "accepted",
                "reported_at": at,
            }
            result["complaint_ref"] = receipt["receipt_id"]
        elif action["action_type"] == "police_report":
            result["transfer_ref"] = new_id("POL")
        elif action["action_type"] == "public_statement":
            result["statement_ref"] = new_id("STM")
        else:
            result["note"] = "内部保护动作已落实"
        self._append("action_executed", {
            "action_id": action_id, "incident_id": action["incident_id"],
            "at": at, "result": result, "receipt": receipt,
        })
        return {"action_id": action_id, "status": "executed", "result": result}

    # ------------------------------------------------------------------ 申诉
    def open_appeal(self, incident_id, reason, actor):
        _require(actor, self.SUBMIT_ROLES)
        inc = self._get_open_incident(incident_id)
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("该事件已在申诉中")
        self._append("appeal_opened", {
            "incident_id": incident_id, "reason": reason,
            "by": actor.get("name"), "at": now_iso(),
        })

    def resolve_appeal(self, incident_id, decision, actor, note=None):
        _require(actor, ("法务复核员",))
        inc = self._get_incident(incident_id)
        if not inc["appeal"] or inc["appeal"]["status"] != "open":
            raise AppError("该事件没有待裁定的申诉")
        if decision not in ("upheld", "dismissed"):
            raise AppError("decision 仅支持 upheld（误报成立）/dismissed（申诉驳回）")
        self._append("appeal_resolved", {
            "incident_id": incident_id, "decision": decision,
            "by": actor.get("name"), "at": now_iso(), "note": note,
        })
        if decision == "upheld":
            self._append("incident_closed", {
                "incident_id": incident_id,
                "reason": "误报申诉成立，按误报关闭（责任链留存）",
                "by": actor.get("name"), "at": now_iso(),
            })

    def close_incident(self, incident_id, reason, actor):
        _require(actor, ("俱乐部保护专员", "法务复核员"))
        inc = self._get_open_incident(incident_id)
        pending = [a for a in inc["actions"] if self.actions[a]["status"] in ("pending", "approved")]
        if inc["escalation"] and inc["escalation"]["status"] == "open":
            raise AppError("值班升级尚未响应，不能关闭事件")
        if pending:
            raise AppError(f"尚有 {len(pending)} 个保护动作未完成，不能关闭事件")
        self._append("incident_closed", {
            "incident_id": incident_id, "reason": reason or "保护动作完成，关闭",
            "by": actor.get("name"), "at": now_iso(),
        })

    # ------------------------------------------------------------------ 回调
    def platform_callback(self, payload):
        """平台/采集回调。以 callback_id 幂等：重复回调不通知、不产生第二案件。"""
        callback_id = payload.get("callback_id")
        if not callback_id:
            raise AppError("回调必须携带 callback_id")
        if callback_id in self.callbacks:
            first = self.callbacks[callback_id]
            return {"duplicate": True, "callback_id": callback_id, **first}

        incident = self._resolve_callback_incident(payload)
        if incident is None:
            raise AppError("回调未匹配到既有事件，须先经当事人或授权代理报送立案", 404)
        incident_id = incident["incident_id"]
        at = now_iso()
        attached = []

        receipt = payload.get("receipt")
        if receipt and receipt.get("receipt_id"):
            self._append("receipt_recorded", {
                "incident_id": incident_id,
                "receipt_id": receipt["receipt_id"],
                "platform": receipt.get("platform", payload.get("platform")),
                "status": receipt.get("status"),
                "reported_at": receipt.get("reported_at", at),
                "via": "callback", "at": at,
            })
            attached.append("receipt")
            if receipt.get("status") == "removed":
                evidence = self._evidence_for(incident, receipt.get("content_url"))
                if evidence:
                    self._append("content_state_changed", {
                        "incident_id": incident_id, "evidence_id": evidence["evidence_id"],
                        "old_state": evidence["state"], "new_state": "deleted",
                        "source": "platform_callback", "at": at,
                    })
                    attached.append("content_deleted")

        account = payload.get("account")
        if account and account.get("account_key"):
            matched = next((a for a in incident["accounts"]
                            if a["platform"] == account.get("platform")
                            and a["account_key"] == account["account_key"]), None)
            if matched:
                new_name = account.get("display_name")
                if new_name and new_name != matched["display_name"]:
                    self._append("account_renamed", {
                        "incident_id": incident_id,
                        "platform": matched["platform"],
                        "account_key": matched["account_key"],
                        "old_name": matched["display_name"],
                        "new_name": new_name, "at": at,
                    })
                    attached.append("account_renamed")
            else:
                self._append("account_linked", {
                    "incident_id": incident_id, "link_id": new_id("acct"),
                    "platform": account.get("platform", payload.get("platform")),
                    "account_key": account["account_key"], "url": account.get("url"),
                    "display_name": account.get("display_name"), "at": at,
                })
                attached.append("account_linked")

        # 回调附件不产生任何通知，也绝不另立案件
        result = {"duplicate": False, "callback_id": callback_id,
                  "incident_id": incident_id, "attached": attached}
        stored = {k: v for k, v in result.items() if k != "duplicate"}
        self.callbacks[callback_id] = stored
        # 事件化记录，保证账本重放（含重启）后幂等索引仍然有效
        self._append("callback_processed", {"callback_id": callback_id, "result": stored, "at": at})
        return result

    def _resolve_callback_incident(self, payload):
        explicit = payload.get("incident_id")
        if explicit and explicit in self.incidents:
            return self.incidents[explicit]
        receipt = payload.get("receipt") or {}
        receipt_id = receipt.get("receipt_id")
        if receipt_id:
            for inc in self.incidents.values():
                if any(r["receipt_id"] == receipt_id for r in inc["receipts"]):
                    return inc
        url = receipt.get("content_url") or payload.get("content_url")
        if url:
            for inc in self.incidents.values():
                if any(e["content_ref"] == url for e in inc["evidence"]):
                    return inc
        return None

    def _evidence_for(self, incident, url):
        if not url:
            return None
        return next((e for e in incident["evidence"] if e["content_ref"] == url), None)

    # ---------------------------------------------------------- 材料保全移交
    def _handoff_key(self, incident_id, org_code, purpose):
        return (incident_id, org_code, purpose)

    def issue_preservation_order(self, incident_id, payload, actor):
        """法务按案件+用途签发带版本、期限、字段范围的保全令；系统随即固化清单与摘要。

        重复移交（同事件+同接收机构+同用途）不发通知、不生成第二份清单：
        拟交内容与已签认清单一致则返回既有令；不一致则进入冲突复核。
        """
        _require(actor, (self.config.handoff["签发角色"],))
        inc = self._get_incident(incident_id)
        purpose = payload.get("purpose")
        if not self.config.is_valid_handoff_purpose(purpose):
            raise AppError(f"未知保全用途：{purpose}")
        receiver = payload.get("receiver") or {}
        org_code = receiver.get("org_code")
        if not org_code:
            raise AppError("必须指定接收机构 receiver.org_code")
        field_scope = payload.get("field_scope")
        if not field_scope:
            raise AppError("保全令必须声明字段范围 field_scope")
        unknown_fields = [f for f in field_scope if not self.config.is_configured_handoff_field(f)]
        if unknown_fields:
            raise AppError(f"未知材料字段：{unknown_fields}")
        # 司法移交必须包含依法最小保全字段
        if purpose == "judicial_transfer":
            missing_min = [f for f in self.config.minimal_preservation_fields if f not in field_scope]
            if missing_min:
                raise AppError(f"司法移交的字段范围必须包含最小保全字段：{missing_min}")

        expires_at = self._resolve_expiry(payload, purpose)
        key = self._handoff_key(incident_id, org_code, purpose)
        existing_id = self._handoff_keys.get(key)
        if existing_id:
            return self._handle_repeat_handoff(
                inc, self.preservation_orders[existing_id], field_scope, actor)

        order_id = new_id("ord")
        at = now_iso()
        self._append("preservation_order_issued", {
            "order_id": order_id, "incident_id": incident_id,
            "case_no": payload.get("case_no"), "version": 1,
            "purpose": purpose, "receiver": receiver,
            "field_scope": field_scope, "issued_at": at, "expires_at": expires_at,
            "issued_by": actor.get("name"),
            "basis": payload.get("basis", "按案件与用途依法保全"),
            "expected_receipts": payload.get("expected_receipts", []),
        })
        manifest = self._generate_manifest(self.preservation_orders[order_id], inc, at)
        self._notify_handoff(incident_id, order_id, manifest["manifest_id"], at)
        return {"order_id": order_id, "version": 1,
                "manifest_id": manifest["manifest_id"], "duplicate": False}

    def _handle_repeat_handoff(self, inc, order, field_scope, actor):
        """重复移交：幂等返回或转冲突复核，绝不另发通知/另造清单。"""
        existing = self.manifests.get(order["manifest_id"])
        current_items = self._build_items(inc, field_scope)
        current_digest = self._digest_of(order["order_id"], order["version"], current_items)
        differences = []
        if existing:
            if set(field_scope) != set(order["field_scope"]):
                differences.append("字段范围与已签认保全令不一致")
            if current_digest != existing["digest"]:
                old = {i["field_code"]: i["item_sha256"] for i in existing["items"]}
                for item in current_items:
                    if old.get(item["field_code"]) != item["item_sha256"]:
                        differences.append(f"字段 {item['field_code']} 内容已变化")
        if not differences:
            return {"order_id": order["order_id"], "version": order["version"],
                    "manifest_id": order["manifest_id"], "duplicate": True,
                    "note": "重复移交：内容一致，沿用既有清单，不重复通知"}
        conflict_id = new_id("cfl")
        at = now_iso()
        self._append("handoff_conflict_raised", {
            "conflict_id": conflict_id, "incident_id": inc["incident_id"],
            "order_id": order["order_id"], "existing_manifest_id": order["manifest_id"],
            "reason": "重复移交但拟交内容与已签认清单不一致",
            "differences": differences, "at": at,
        })
        return {"order_id": order["order_id"], "duplicate": True, "conflict_id": conflict_id,
                "note": "重复移交内容发生变化，已进入冲突复核，未生成第二份清单、未重复通知"}

    def resolve_handoff_conflict(self, conflict_id, decision, actor, note=None):
        _require(actor, ("法务复核员", "俱乐部保护专员"))
        conflict = self.conflicts.get(conflict_id)
        if not conflict:
            raise AppError("冲突复核任务不存在", 404)
        if conflict["status"] != "open":
            raise AppError("该冲突已复核")
        if decision not in ("issue_new_version", "keep_existing"):
            raise AppError("decision 仅支持 issue_new_version/keep_existing")
        at = now_iso()
        new_order_id = None
        if decision == "issue_new_version":
            inc = self._get_incident(conflict["incident_id"])
            old = self.preservation_orders[conflict["order_id"]]
            new_order_id = self._issue_new_version(old, inc, actor, at)
        self._append("handoff_conflict_resolved", {
            "conflict_id": conflict_id, "decision": decision,
            "by": actor.get("name"), "at": at, "note": note,
            "new_order_id": new_order_id,
        })
        return {"conflict_id": conflict_id, "decision": decision,
                "new_order_id": new_order_id}

    def _issue_new_version(self, old, inc, actor, at):
        """冲突复核确认内容确需更新披露时，签发新版本保全令并固化新清单。"""
        new_id_ = new_id("ord")
        self._append("preservation_order_issued", {
            "order_id": new_id_, "incident_id": inc["incident_id"],
            "case_no": old["case_no"],
            "version": old["version"] + 1,
            "purpose": old["purpose"], "receiver": old["receiver"],
            "field_scope": list(old["field_scope"]),
            "issued_at": at, "expires_at": old["expires_at"],
            "issued_by": actor.get("name"),
            "basis": old["basis"], "supersedes": old["order_id"],
        })
        self._append("preservation_order_superseded", {
            "order_id": old["order_id"], "superseded_by": new_id_, "at": at})
        new_order = self.preservation_orders[new_id_]
        self._generate_manifest(new_order, inc, at)
        return new_id_

    def _generate_manifest(self, order, inc, at):
        items = self._build_items(inc, order["field_scope"])
        digest = self._digest_of(order["order_id"], order["version"], items)
        manifest_id = new_id("man")
        self._append("manifest_generated", {
            "manifest_id": manifest_id, "order_id": order["order_id"],
            "incident_id": inc["incident_id"], "order_version": order["version"],
            "generated_at": at, "digest": digest, "items": items,
        })
        return self.manifests[manifest_id]

    def _build_items(self, inc, field_scope):
        values = self._field_values(inc)
        items = []
        for code in field_scope:
            spec = self.config.handoff_fields[code]
            value = values.get(code)
            items.append({
                "field_code": code,
                "name": spec["名称"],
                "minimal": bool(spec["最小保全"]),
                "included": value is not None and value != [] and value != {},
                "value": value,
                "item_sha256": self._sha_of(value),
            })
        return items

    def _field_values(self, inc):
        return {
            "victim_code": inc["victim_code"],
            "content_ref": [e["content_ref"] for e in inc["evidence"]],
            "content_sha256": [e["content_sha256"] for e in inc["evidence"] if e["content_sha256"]],
            "evidence_note": [e["note"] for e in inc["evidence"] if e.get("note")],
            "linked_accounts": [
                {"platform": a["platform"], "account_key": a["account_key"],
                 "display_name": a.get("display_name")}
                for a in inc["accounts"]],
            "platform_receipts": [
                {"receipt_id": r["receipt_id"], "platform": r["platform"], "status": r["status"]}
                for r in inc["receipts"]],
            "action_chain": [
                {"action_id": aid, "type": self.actions[aid]["action_type"],
                 "status": self.actions[aid]["status"]}
                for aid in inc["actions"]],
            "raw_contact": inc.get("raw_contact"),
        }

    def _digest_of(self, order_id, version, items):
        canonical = json.dumps(
            {"order_id": order_id, "version": version,
             "items": [{"f": i["field_code"], "h": i["item_sha256"]} for i in items]},
            ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _sha_of(self, value):
        return hashlib.sha256(
            json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()

    def _resolve_expiry(self, payload, purpose):
        if payload.get("expires_at"):
            return payload["expires_at"]
        days = payload.get("duration_days")
        if days is None:
            days = self.config.default_handoff_days(purpose)
        return (datetime.now(CST) + timedelta(days=int(days))).isoformat(timespec="seconds")

    def _notify_handoff(self, incident_id, order_id, manifest_id, at):
        """首次移交：通知交出方与接收方签认；重复移交路径不调用本方法。"""
        for role in self.config.handoff_surrender_roles:
            self._append("notification_sent", {
                "notif_id": new_id("ntf"), "incident_id": incident_id,
                "channel": "handoff", "to_role": role, "reason": "保全材料待交出方签认",
                "order_id": order_id, "manifest_id": manifest_id, "at": at})
        for role in self.config.handoff_receiver_roles:
            self._append("notification_sent", {
                "notif_id": new_id("ntf"), "incident_id": incident_id,
                "channel": "handoff", "to_role": role, "reason": "保全材料待接收方签认",
                "order_id": order_id, "manifest_id": manifest_id, "at": at})

    # ------------------------------------------------------ 签认/拒收/退回
    def acknowledge_manifest(self, manifest_id, actor, note=None):
        manifest = self._get_manifest(manifest_id)
        party = self._manifest_party(actor)
        if manifest["status"] in ("returned",):
            raise AppError("清单已被退回，须经补件并生成衔接清单后再签认")
        ack = manifest["surrender_ack"] if party == "surrender" else manifest["receiver_ack"]
        if ack:
            raise AppError(f"{party} 方已签认，不得改写先前签认回执")
        self._append("manifest_acknowledged", {
            "manifest_id": manifest_id, "party": party,
            "by": actor.get("name"), "by_role": actor["role"],
            "at": now_iso(), "note": note,
        })
        return {"manifest_id": manifest_id, "party": party, "status": self.manifests[manifest_id]["status"]}

    def _manifest_party(self, actor):
        if actor["role"] in self.config.handoff_surrender_roles:
            return "surrender"
        if actor["role"] in self.config.handoff_receiver_roles:
            return "receiver"
        raise AppError(f"角色 {actor['role']} 不是保全移交的交出方或接收方", 403)

    def reject_manifest_items(self, manifest_id, item_fields, reason, actor):
        """接收方部分拒收：只追加拒收事件，原清单与已签认回执保持不变。"""
        _require(actor, self.config.handoff_receiver_roles)
        manifest = self._get_manifest(manifest_id)
        valid = {i["field_code"] for i in manifest["items"]}
        bad = [f for f in item_fields if f not in valid]
        if bad:
            raise AppError(f"清单不含这些字段，无法拒收：{bad}")
        at = now_iso()
        self._append("manifest_event_appended", {
            "manifest_id": manifest_id, "kind": "partial_rejection",
            "by": actor.get("name"), "by_role": actor["role"], "at": at,
            "detail": {"item_fields": item_fields, "reason": reason},
        })
        return {"manifest_id": manifest_id, "status": "partial_rejection",
                "rejected_fields": item_fields}

    def return_manifest(self, manifest_id, reason, actor):
        """接收方整批退回（来源/责任/授权期限无法确认）：只追加，不改写。"""
        _require(actor, self.config.handoff_receiver_roles)
        manifest = self._get_manifest(manifest_id)
        if reason not in self.config.handoff["退回原因"]:
            raise AppError(f"退回原因须为：{self.config.handoff['退回原因']}")
        at = now_iso()
        self._append("manifest_event_appended", {
            "manifest_id": manifest_id, "kind": "returned",
            "by": actor.get("name"), "by_role": actor["role"], "at": at,
            "detail": {"reason": reason},
        })
        return {"manifest_id": manifest_id, "status": "returned", "reason": reason}

    def supplement_manifest(self, manifest_id, item_fields, actor, note=None):
        """交出方补件：补件字段必须仍在当前保全令授权范围内，否则须重新核权出新版本。"""
        _require(actor, self.config.handoff_surrender_roles)
        manifest = self._get_manifest(manifest_id)
        if manifest["status"] == "returned":
            raise AppError("清单已被整批退回，补件须由法务重新签发保全令并生成新清单", 409)
        order = self.preservation_orders[manifest["order_id"]]
        beyond = [f for f in item_fields if f not in order["field_scope"]]
        if beyond:
            raise AppError(
                f"补件字段 {beyond} 超出原保全令披露范围，任何新增披露须重新核权并签发新版本", 409)
        if order["status"] != "active" or self._order_expired(order):
            raise AppError("保全令已失效或到期，补件前须由法务重新签发/延长", 409)
        # 在字段范围内补件，只有补齐清单已封存（哈希一致）的内容才允许直接追加；
        # 若该字段内容相对签认清单已发生变化（新增证据/新回执），属于新增披露，
        # 必须重新核权并经冲突复核签发新版本，不能借补件扩写到旧清单。
        inc = self.incidents[manifest["incident_id"]]
        sealed = {i["field_code"]: i["item_sha256"] for i in manifest["items"]}
        current = {i["field_code"]: i["item_sha256"]
                   for i in self._build_items(inc, order["field_scope"])}
        new_disclosure = [f for f in item_fields if current.get(f) != sealed.get(f)]
        if new_disclosure:
            raise AppError(
                f"补件字段 {new_disclosure} 含清单封存之外的新增内容，"
                "任何新增披露须重新核权并签发新版本", 409)
        at = now_iso()
        self._append("manifest_event_appended", {
            "manifest_id": manifest_id, "kind": "supplemented",
            "by": actor.get("name"), "by_role": actor["role"], "at": at,
            "detail": {"item_fields": item_fields, "note": note,
                       "order_version": order["version"], "order_expires_at": order["expires_at"]},
        })
        return {"manifest_id": manifest_id, "status": self.manifests[manifest_id]["status"],
                "supplemented_fields": item_fields}

    def extend_preservation(self, order_id, actor, reason, duration_days=None, new_expires_at=None):
        """法务延长保全期限；司法延长标记 judicial，仅追加延长事件。"""
        _require(actor, (self.config.handoff["签发角色"],))
        order = self.preservation_orders.get(order_id)
        if not order:
            raise AppError("保全令不存在", 404)
        judicial = "司法" in (reason or "")
        if new_expires_at is None:
            base = datetime.fromisoformat(order["expires_at"])
            if duration_days is None:
                raise AppError("延长须提供 duration_days 或 new_expires_at")
            new_expires_at = (base + timedelta(days=int(duration_days))).isoformat(timespec="seconds")
        previous = order["expires_at"]
        at = now_iso()
        self._append("preservation_extended", {
            "order_id": order_id, "previous_expires_at": previous,
            "new_expires_at": new_expires_at, "reason": reason,
            "judicial": judicial, "by": actor.get("name"), "at": at,
        })
        return {"order_id": order_id, "expires_at": new_expires_at, "judicial": judicial}

    def _get_manifest(self, manifest_id):
        manifest = self.manifests.get(manifest_id)
        if not manifest:
            raise AppError("材料清单不存在", 404)
        return manifest

    def _order_expired(self, order):
        try:
            return datetime.fromisoformat(order["expires_at"]) < datetime.now(CST)
        except ValueError:
            return False

    def _judicial_hold(self, inc):
        """司法移交或已报案移交且保全令仍有效：依法留存，不受个人授权撤回影响。"""
        if self._has_executed(inc["incident_id"], "police_report"):
            return True
        for order in self._orders_for(inc["incident_id"]):
            if order["purpose"] == "judicial_transfer" and not self._order_expired(order):
                return True
        return False

    def _orders_for(self, incident_id):
        return [o for o in self.preservation_orders.values()
                if o["incident_id"] == incident_id and o["status"] == "active"]

    def _has_active_preservation(self, incident_id):
        return any(not self._order_expired(o) for o in self._orders_for(incident_id))

    # ------------------------------------------------------------------ 查询
    def _get_incident(self, incident_id):
        inc = self.incidents.get(incident_id)
        if not inc:
            raise AppError("事件不存在", 404)
        return inc

    def _get_open_incident(self, incident_id):
        inc = self._get_incident(incident_id)
        if inc.get("merged_into"):
            raise AppError(f"该事件已合并入 {inc['merged_into']}，请在主事件上操作", 409)
        if inc.get("closed_at"):
            raise AppError("事件已关闭，不可再变更", 409)
        return inc

    def _assert_not_appealed(self, inc):
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("申诉期间限制敏感材料扩散，须先由法务复核员裁定")

    def _status_of(self, inc):
        if inc.get("closed_at"):
            return "已关闭"
        if inc.get("merged_into"):
            return "已关闭"
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            return "申诉中"
        if self._has_executed(inc["incident_id"], "police_report"):
            return "已移交"
        if any(self.actions[a]["status"] == "pending" for a in inc["actions"]):
            return "待复核"
        if inc["actions"] or inc["escalation"]:
            return "保护中"
        return "已受理"

    def incident_digest(self, incident_id, as_role=None):
        """保护专员视角的统一视图：证据依据、处置决定、授权范围、待办保护动作。"""
        inc = self._get_incident(incident_id)
        appeal_open = inc["appeal"] and inc["appeal"]["status"] == "open"
        mask = appeal_open and not (as_role and self.config.appeal_can_view_sensitive(as_role))

        evidence = [{
            "evidence_id": e["evidence_id"], "kind": e["kind"],
            "content_ref": "【申诉期间已限制查看】" if mask else e["content_ref"],
            "content_sha256": e["content_sha256"], "state": e["state"],
            "submitted_by": e["submitted_by"], "at": e["at"], "note": e["note"],
        } for e in inc["evidence"]]

        accounts = [{
            "platform": "【申诉期间已限制】" if mask else a["platform"],
            "account_key": "【申诉期间已限制】" if mask else a["account_key"],
            "url": "【申诉期间已限制】" if mask else a.get("url"),
            "display_name": "【申诉期间已限制】" if mask else a.get("display_name"),
            "renamed": len(a["name_history"]) > 1,
            "name_history": [] if mask else a["name_history"],
        } for a in inc["accounts"]]

        actions = [self._action_view(a, inc) for a in inc["actions"]]
        pending = [a["action_id"] for a in actions if a["status"] in ("pending", "approved", "blocked")]

        digest = {
            "incident_id": inc["incident_id"],
            "status": self._status_of(inc),
            "victim_code": inc["victim_code"],
            "platform": inc["platform"],
            "severity": self.config.severities[inc["severity"]],
            "report_nos": inc["report_nos"],
            "opened_at": inc["opened_at"],
            "merged_into": inc.get("merged_into"),
            "absorbed_incidents": inc.get("absorbed", []),
            "证据依据": {
                "evidence": evidence,
                "linked_accounts": accounts,
                "platform_receipts": inc["receipts"],
            },
            "处置决定": actions,
            "当事人当前授权范围": [
                {"code": s, "name": self.config.scopes[s]["名称"]}
                for s in inc["consent_scopes"]
            ],
            "尚未完成的保护动作": {
                "action_ids": pending,
                "open_escalation": bool(inc["escalation"] and inc["escalation"]["status"] == "open"),
            },
            "值班升级": inc["escalation"],
            "申诉": inc["appeal"],
            "责任链": self._timeline(inc, mask),
        }
        if inc.get("closed_at"):
            digest["closed_at"] = inc["closed_at"]
            digest["close_reason"] = inc["close_reason"]
        return digest

    def case_trace(self, incident_id, as_role=None):
        """案件追溯：逐项说明材料为何保全、由谁保管、何时到期、缺失哪些外部回执。

        普通案件查看者只能获得角色允许的脱敏内容。
        """
        inc = self._get_incident(incident_id)
        masked = bool(as_role and self.config.handoff_view_is_masked(as_role))
        received_ids = {r["receipt_id"] for r in inc["receipts"]}

        orders_view = []
        for order in self._all_orders_for(incident_id):
            manifest = self.manifests.get(order["manifest_id"])
            custodian = self._custodian_of(order, manifest)
            missing = [{"receipt_id": self._mask_value("platform_receipts", e.get("receipt_id"), masked),
                        "platform": e.get("platform")}
                       for e in order["expected_receipts"]
                       if e.get("receipt_id") not in received_ids]
            orders_view.append({
                "order_id": order["order_id"],
                "case_no": order["case_no"],
                "version": order["version"],
                "purpose": self.config.handoff_purposes[order["purpose"]]["名称"],
                "receiver": self._mask_receiver(order["receiver"], masked),
                "status": order["status"],
                "issued_at": order["issued_at"],
                "issued_by": order["issued_by"],
                "expires_at": order["expires_at"],
                "expired": self._order_expired(order),
                "supersedes": order.get("supersedes"),
                "judicial_extensions": [e for e in order["extensions"] if e.get("judicial")],
                "custodian": custodian,
                "manifest_id": order["manifest_id"],
                "manifest_status": manifest["status"] if manifest else None,
                "surrender_ack": self._mask_ack(manifest, "surrender_ack", masked),
                "receiver_ack": self._mask_ack(manifest, "receiver_ack", masked),
                "missing_external_receipts": missing,
                "followup_events": list(manifest["events"]) if manifest else [],
                "items": self._trace_items(inc, order, manifest, custodian, masked),
            })

        return {
            "incident_id": inc["incident_id"],
            "case_no": next((o["case_no"] for o in orders_view if o["case_no"]), None),
            "status": self._status_of(inc),
            "masked": masked,
            "minimal_preservation_fields": self.config.minimal_preservation_fields,
            "judicial_hold": self._judicial_hold(inc),
            "preservation_orders": orders_view,
            "conflicts": [c for c in self.conflicts.values()
                          if c["incident_id"] == incident_id],
        }

    def _trace_items(self, inc, order, manifest, custodian, masked):
        values = self._field_values(inc)
        items = []
        for code in order["field_scope"]:
            spec = self.config.handoff_fields[code]
            minimal = bool(spec["最小保全"])
            why = ("依法/司法存续所需最小材料，授权撤回或账号改名后仍继续留存"
                   if minimal else f"按保全令 {order['order_id']}（{self.config.handoff_purposes[order['purpose']]['名称']}）披露范围保全")
            value = values.get(code)
            items.append({
                "field_code": code,
                "name": spec["名称"],
                "minimal": minimal,
                "why_preserved": why,
                "custodian": custodian,
                "expires_at": order["expires_at"],
                "present": value is not None and value != [] and value != {},
                "value": self._mask_value(code, value, masked),
            })
        return items

    def _all_orders_for(self, incident_id):
        return [o for o in self.preservation_orders.values()
                if o["incident_id"] == incident_id]

    def _custodian_of(self, order, manifest):
        if manifest and manifest["receiver_ack"]:
            org = order["receiver"].get("org_name") or order["receiver"].get("org_code")
            return f"接收方：{org}（已签认接收）"
        if manifest and manifest["surrender_ack"]:
            return "交出方：俱乐部（已签认交出，待接收方签认）"
        return "交出方：俱乐部（尚未完成签认）"

    def _mask_receiver(self, receiver, masked):
        if not masked:
            return receiver
        return {"org_code": self.config.handoff["脱敏查看"]["掩码"],
                "org_name": self.config.handoff["脱敏查看"]["掩码"]}

    def _mask_ack(self, manifest, key, masked):
        if not manifest or not manifest.get(key):
            return None
        ack = dict(manifest[key])
        if masked:
            ack["by"] = self.config.handoff["脱敏查看"]["掩码"]
        return ack

    def _mask_value(self, field_code, value, masked):
        if not masked or value is None:
            return value
        if self.config.handoff_mask(field_code) is None:
            return value
        token = self.config.handoff["脱敏查看"]["掩码"]
        if isinstance(value, str):
            return token
        if isinstance(value, list):
            return [self._mask_value(field_code, v, masked) for v in value]
        if isinstance(value, dict):
            return {k: self._mask_value(field_code, v, masked) for k, v in value.items()}
        return token

    def list_preservation_orders(self, incident_id=None):
        orders = self._all_orders_for(incident_id) if incident_id \
            else list(self.preservation_orders.values())
        return [{
            "order_id": o["order_id"], "incident_id": o["incident_id"],
            "case_no": o["case_no"], "version": o["version"],
            "purpose": o["purpose"], "receiver": o["receiver"],
            "status": o["status"], "expires_at": o["expires_at"],
            "manifest_id": o["manifest_id"],
        } for o in orders]

    def get_manifest(self, manifest_id, as_role=None):
        manifest = self._get_manifest(manifest_id)
        masked = bool(as_role and self.config.handoff_view_is_masked(as_role))
        view = {k: v for k, v in manifest.items()}
        if masked:
            view["items"] = [{**i, "value": self._mask_value(i["field_code"], i["value"], True)}
                             for i in manifest["items"]]
        return view

    def list_conflicts(self, status="open"):
        return [c for c in self.conflicts.values() if status is None or c["status"] == status]

    def _action_view(self, action_id, inc):
        a = self.actions[action_id]
        view = {
            "action_id": a["action_id"], "action_type": a["action_type"],
            "name": self.config.actions[a["action_type"]]["名称"],
            "status": a["status"], "proposed_by": a["proposed_by"],
            "proposed_by_role": a["proposed_by_role"],
            "required_reviewer_role": a["required_reviewer_role"],
            "reviewer": a["reviewer"], "review_reason": a["review_reason"],
            "executed_at": a["executed_at"], "result": a["result"],
        }
        if a["status"] == "approved":
            missing = [s for s in a["required_scopes"] if s not in inc["consent_scopes"]]
            if missing:
                view["status"] = "blocked"
                view["blocked_reason"] = "授权已撤回：" + "、".join(
                    self.config.scopes[s]["名称"] for s in missing)
        return view

    def _timeline(self, inc, mask):
        wanted = set(inc["report_nos"])
        incident_ids = {inc["incident_id"]}
        for absorbed_id in inc.get("absorbed", []):
            absorbed = self.incidents.get(absorbed_id)
            if absorbed:
                incident_ids.add(absorbed_id)
                wanted.update(absorbed["report_nos"])
        chain = []
        for event in self.store.replay():
            p = event["payload"]
            if p.get("incident_id") in incident_ids or p.get("report_no") in wanted:
                chain.append({"seq": event["seq"], "type": event["type"], "payload": p})
        if mask:
            for item in chain:
                p = item["payload"]
                for field in ("content_ref", "content_url", "raw_excerpt", "url", "display_name"):
                    if field in p and p[field]:
                        p[field] = "【申诉期间已限制】"
                if "linked_accounts" in p:
                    p["linked_accounts"] = ["【申诉期间已限制】" for _ in p["linked_accounts"]]
        return chain

    def list_incidents(self, status=None, severity=None):
        out = []
        for incident_id, inc in self.incidents.items():
            current = self._status_of(inc)
            if status and current != status:
                continue
            if severity and inc["severity"] != severity:
                continue
            out.append({
                "incident_id": incident_id, "status": current,
                "victim_code": inc["victim_code"], "severity": inc["severity"],
                "platform": inc["platform"], "opened_at": inc["opened_at"],
                "merged_into": inc.get("merged_into"),
                "open_escalation": bool(inc["escalation"] and inc["escalation"]["status"] == "open"),
            })
        return out

    def list_suggestions(self, status="open"):
        return [s for s in self.suggestions.values() if status is None or s["status"] == status]

    def list_reports(self):
        return list(self.reports.values())

    def list_notifications(self, incident_id=None):
        if incident_id:
            return [n for n in self.notifications if n["incident_id"] == incident_id]
        return list(self.notifications)
