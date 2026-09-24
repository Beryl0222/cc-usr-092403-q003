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
        self.orders = {}             # preservation_order_id -> 保全令投影
        self.manifests = {}          # manifest_id -> 不可变材料清单快照
        self.handoffs = {}           # handoff_id -> 外部移交投影
        self.conflicts = {}          # conflict_id -> 移交冲突复核
        self._handoff_keys = {}      # (order_id, receiver_org, purpose) -> handoff_id
        self._suggestion_keys = set()
        self._last_seq = 0
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
        self._last_seq = event["seq"]
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
            "preservation_orders": [],
            "handoffs": [],
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

    # ------------------------------------------------------- 保全令/清单/移交
    def _on_preservation_order_issued(self, p):
        self.orders[p["order_id"]] = {
            "order_id": p["order_id"], "incident_id": p["incident_id"],
            "version": p["version"], "supersedes": p.get("supersedes"),
            "purpose": p["purpose"], "field_groups": list(p["field_groups"]),
            "fields": list(p["fields"]),
            "issued_by": p["issued_by"], "issued_at": p["at"],
            "valid_from": p["valid_from"], "valid_until": p["valid_until"],
            "status": "active",
            "superseded_by": None,
            "extensions": [],
            "manifest_ids": [],
        }
        inc = self.incidents.get(p["incident_id"])
        if inc and p["order_id"] not in inc["preservation_orders"]:
            inc["preservation_orders"].append(p["order_id"])
        prev = p.get("supersedes")
        if prev and prev in self.orders:
            self.orders[prev]["status"] = "superseded"
            self.orders[prev]["superseded_by"] = p["order_id"]

    def _on_preservation_extended(self, p):
        order = self.orders.get(p["order_id"])
        if order:
            order["valid_until"] = p["new_valid_until"]
            order["extensions"].append({
                "extension_id": p["extension_id"], "kind": p["kind"],
                "reason": p["reason"], "granted_by": p["by"],
                "at": p["at"], "new_valid_until": p["new_valid_until"],
                "legal_ref": p.get("legal_ref"),
            })

    def _on_manifest_generated(self, p):
        self.manifests[p["manifest_id"]] = {
            "manifest_id": p["manifest_id"], "order_id": p["order_id"],
            "order_version": p["order_version"], "incident_id": p["incident_id"],
            "purpose": p["purpose"], "fields": list(p["fields"]),
            "generated_at": p["at"],
            "items": list(p["items"]),
            "summary": dict(p["summary"]),
            "manifest_sha256": p["manifest_sha256"],
        }
        order = self.orders.get(p["order_id"])
        if order and p["manifest_id"] not in order["manifest_ids"]:
            order["manifest_ids"].append(p["manifest_id"])

    def _on_handoff_created(self, p):
        self.handoffs[p["handoff_id"]] = {
            "handoff_id": p["handoff_id"], "incident_id": p["incident_id"],
            "order_id": p["order_id"], "manifest_id": p["manifest_id"],
            "purpose": p["purpose"],
            "receiver_org": p["receiver_org"], "receiver_contact": p.get("receiver_contact"),
            "handover_by": p["handover_by"], "created_at": p["at"],
            "state": "pending_surrender",
            "surrender_ack": None,
            "receiver_ack": None,
            "rejection": None,
            "returned": None,
            "supplement_of": p.get("supplement_of"),
            "last_event_seq": self._last_seq,
            "conflict_accepted": False,
            "events": [{"type": "handoff_created", "at": p["at"]}],
        }
        inc = self.incidents.get(p["incident_id"])
        if inc and p["handoff_id"] not in inc["handoffs"]:
            inc["handoffs"].append(p["handoff_id"])
        if not p.get("supplement_of"):
            self._handoff_keys[(p["order_id"], p["receiver_org"], p["purpose"])] = p["handoff_id"]

    def _touch_handoff(self, p, state=None, event_type=None):
        h = self.handoffs.get(p["handoff_id"])
        if not h:
            return
        if state:
            h["state"] = state
        h["last_event_seq"] = self._last_seq
        if event_type:
            h["events"].append({"type": event_type, "at": p["at"]})

    def _on_handoff_surrender_acknowledged(self, p):
        h = self.handoffs.get(p["handoff_id"])
        if h:
            h["surrender_ack"] = {"by": p["by"], "role": p["role"], "at": p["at"]}
            self._touch_handoff(p, state="pending_receiver",
                                event_type="surrender_acknowledged")

    def _on_handoff_receiver_acknowledged(self, p):
        h = self.handoffs.get(p["handoff_id"])
        if h:
            h["receiver_ack"] = {"by": p["by"], "at": p["at"], "note": p.get("note")}
            self._touch_handoff(p, state="acknowledged",
                                event_type="receiver_acknowledged")

    def _on_handoff_rejected(self, p):
        h = self.handoffs.get(p["handoff_id"])
        if h:
            h["rejection"] = {"reason": p["reason"], "detail": p.get("detail"),
                              "items": p.get("items", []),
                              "by": p["by"], "at": p["at"]}
            self._touch_handoff(p, state="rejected", event_type="rejected")

    def _on_handoff_returned(self, p):
        h = self.handoffs.get(p["handoff_id"])
        if h:
            h["returned"] = {"reason": p["reason"], "detail": p.get("detail"),
                             "items": p.get("items", []),
                             "by": p["by"], "at": p["at"]}
            self._touch_handoff(p, state="returned", event_type="returned")

    def _on_handoff_supplemented(self, p):
        h = self.handoffs.get(p["handoff_id"])
        if h:
            h["manifest_id"] = p["manifest_id"]
            h["state"] = "pending_receiver"
            h["conflict_accepted"] = False
            self._touch_handoff(p, state="pending_receiver",
                                event_type="supplemented")

    def _on_handoff_conflict_raised(self, p):
        h = self.handoffs.get(p["handoff_id"])
        self.conflicts[p["conflict_id"]] = {
            "conflict_id": p["conflict_id"], "handoff_id": p["handoff_id"],
            "incident_id": p["incident_id"], "differences": list(p["differences"]),
            "detected_at": p["at"], "status": "open",
            "resolved_by": None, "resolved_at": None, "decision": None,
        }
        if h:
            self._touch_handoff(p, state="conflict_review",
                                event_type="conflict_raised")

    def _on_handoff_conflict_resolved(self, p):
        conflict = self.conflicts.get(p["conflict_id"])
        if conflict:
            conflict["status"] = "resolved"
            conflict["decision"] = p["decision"]
            conflict["resolved_by"] = p["by"]
            conflict["resolved_at"] = p["at"]
            conflict["note"] = p.get("note")
        h = self.handoffs.get(p["handoff_id"])
        if h:
            if p["decision"] == "accept_existing":
                # 复核维持原清单：差异已裁断，重复移交按幂等处理，不再重复开冲突
                h["state"] = "acknowledged"
                h["conflict_accepted"] = True
            else:
                h["state"] = "supplement_required"
            h["events"].append({"type": "conflict_resolved", "at": p["at"]})

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

    # ============================================================ 保全令/外部移交
    DISCLOSURE_SCOPE = "external_disclosure"

    def _parse_iso(self, value):
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            raise AppError(f"时间格式不合法（需 ISO-8601）：{value}")

    def _assert_not_merged(self, inc):
        if inc.get("merged_into"):
            raise AppError(f"该事件已合并入 {inc['merged_into']}，请在主事件上操作", 409)

    def _order(self, order_id):
        order = self.orders.get(order_id)
        if not order:
            raise AppError("保全令不存在", 404)
        return order

    def _handoff(self, handoff_id):
        handoff = self.handoffs.get(handoff_id)
        if not handoff:
            raise AppError("移交记录不存在", 404)
        return handoff

    def _assert_disclosure_authorized(self, inc):
        """新增对外披露必须当前持有 external_disclosure 授权（撤回后须重新核权）。"""
        if self.DISCLOSURE_SCOPE not in inc["consent_scopes"]:
            raise AppError("当事人对外移交披露授权不足或已撤回，新增披露须重新核权后再进行", 409)

    def _assert_disclosure_open(self, inc):
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("误报申诉期间不得对外移交新材料", 409)

    # ------------------------------------------------------------- 保全令签发
    def issue_preservation_order(self, incident_id, payload, actor):
        """法务按案件+用途签发带版本、期限、字段范围的保全令，并生成不可变清单。"""
        _require(actor, tuple(self.config.handoff["保全令签发角色"]))
        inc = self._get_incident(incident_id)
        self._assert_not_merged(inc)

        purpose = payload.get("purpose")
        if purpose not in self.config.handoff_purposes:
            raise AppError(f"未知移交用途：{purpose}")
        groups = payload.get("field_groups") or self.config.default_field_scope
        unknown_groups = set(groups) - set(self.config.handoff_field_groups)
        if unknown_groups:
            raise AppError(f"未知字段范围分组：{sorted(unknown_groups)}")
        fields = self.config.fields_for_groups(groups)

        valid_from = payload.get("valid_from") or now_iso()
        valid_until = payload.get("valid_until")
        if not valid_until:
            raise AppError("保全令必须载明授权期限 valid_until")
        if self._parse_iso(valid_until) <= self._parse_iso(valid_from):
            raise AppError("保全令到期日必须晚于生效日")

        supersedes = payload.get("supersedes")
        active_same_purpose = [oid for oid, o in self.orders.items()
                               if o["incident_id"] == incident_id and o["purpose"] == purpose
                               and o["status"] == "active"]
        if supersedes:
            old = self._order(supersedes)
            if old["incident_id"] != incident_id or old["purpose"] != purpose:
                raise AppError("被替换的保全令必须属于同一案件与同一用途")
            active_same_purpose = [oid for oid in active_same_purpose if oid != supersedes]
        if active_same_purpose:
            raise AppError(
                f"该案件用途已存在生效保全令 {active_same_purpose[0]}，变更须显式 supersedes 换版", 409)
        version = self._next_version(supersedes)

        order_id = new_id("po")
        at = now_iso()
        self._append("preservation_order_issued", {
            "order_id": order_id, "incident_id": incident_id,
            "version": version, "supersedes": supersedes,
            "purpose": purpose, "field_groups": groups, "fields": fields,
            "valid_from": valid_from, "valid_until": valid_until,
            "issued_by": actor.get("name"), "at": at,
        })
        manifest = self._generate_manifest(order_id)
        return {"order_id": order_id, "version": version, "supersedes": supersedes,
                "purpose": purpose, "purpose_name": self.config.purpose_name(purpose),
                "valid_from": valid_from, "valid_until": valid_until,
                "field_groups": groups, "fields": fields,
                "manifest_id": manifest["manifest_id"],
                "manifest_sha256": manifest["manifest_sha256"]}

    def _next_version(self, supersedes):
        if not supersedes:
            return "v1"
        old_version = self._order(supersedes)["version"]
        try:
            return f"v{int(old_version.lstrip('v')) + 1}"
        except ValueError:
            return f"{old_version}.1"

    def extend_preservation_order(self, order_id, payload, actor):
        """司法延长：只追加延长期限事件，保全令本体与既有清单不变。"""
        _require(actor, tuple(self.config.handoff["保全令签发角色"]))
        order = self._order(order_id)
        if order["status"] != "active":
            raise AppError("仅生效中的保全令可以延期")
        new_until = payload.get("new_valid_until")
        if not new_until:
            raise AppError("延期必须提供 new_valid_until")
        if self._parse_iso(new_until) <= self._parse_iso(order["valid_until"]):
            raise AppError("延期后的到期日必须晚于当前到期日")
        kind = payload.get("kind", "judicial_extension")
        if kind == "judicial_extension" and not payload.get("legal_ref"):
            raise AppError("司法延长必须附法律文书编号 legal_ref")
        extension_id = new_id("ext")
        self._append("preservation_extended", {
            "extension_id": extension_id, "order_id": order_id, "kind": kind,
            "reason": payload.get("reason", "司法程序需要，延长保全期限"),
            "legal_ref": payload.get("legal_ref"),
            "new_valid_until": new_until, "by": actor.get("name"), "at": now_iso(),
        })
        return {"order_id": order_id, "extension_id": extension_id,
                "valid_until": new_until}

    # ------------------------------------------------------------- 不可变清单
    def _generate_manifest(self, order_id, supersedes_manifest=None):
        order = self._order(order_id)
        inc = self.incidents[order["incident_id"]]
        items = self._manifest_items(inc, set(order["fields"]))
        summary = self._manifest_summary(inc, items, order)
        canonical = json.dumps(
            {"order_id": order_id, "version": order["version"],
             "purpose": order["purpose"], "items": items},
            sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        manifest_id = new_id("man")
        at = now_iso()
        self._append("manifest_generated", {
            "manifest_id": manifest_id, "order_id": order_id,
            "order_version": order["version"], "incident_id": inc["incident_id"],
            "purpose": order["purpose"], "fields": order["fields"],
            "items": items, "summary": summary,
            "manifest_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "supersedes_manifest": supersedes_manifest, "at": at,
        })
        return self.manifests[manifest_id]

    def _manifest_items(self, inc, field_set):
        groups = self.config.handoff_field_groups
        group_active = {group: bool(set(fields) & field_set)
                        for group, fields in groups.items()}
        items = []
        if group_active["evidence"]:
            for e in inc["evidence"]:
                data = {k: e.get(k) for k in groups["evidence"] if k in field_set}
                if data:
                    items.append({"category": "evidence", "item_id": e["evidence_id"], "data": data})
        if group_active["account"]:
            for a in inc["accounts"]:
                data = {k: a.get(k) for k in groups["account"] if k in field_set}
                if data:
                    items.append({"category": "account", "item_id": a["link_id"], "data": data})
        if group_active["receipt"]:
            for r in inc["receipts"]:
                data = {k: r.get(k) for k in groups["receipt"] if k in field_set}
                if data:
                    items.append({"category": "receipt", "item_id": r["receipt_id"], "data": data})
        if group_active["case"]:
            case_values = {"incident_id": inc["incident_id"], "severity": inc["severity"],
                           "victim_code": inc["victim_code"], "opened_at": inc["opened_at"]}
            data = {k: case_values.get(k) for k in groups["case"] if k in field_set}
            if data:
                items.append({"category": "case", "item_id": inc["incident_id"], "data": data})
        return items

    def _manifest_summary(self, inc, items, order):
        counts = {"evidence": 0, "account": 0, "receipt": 0, "case": 0}
        evidence_hashes = []
        for item in items:
            counts[item["category"]] += 1
            if item["category"] == "evidence" and item["data"].get("content_sha256"):
                evidence_hashes.append(item["data"]["content_sha256"])
        return {"purpose": order["purpose"],
                "purpose_name": self.config.purpose_name(order["purpose"]),
                "material_counts": counts,
                "evidence_sha256": sorted(evidence_hashes),
                "retention_until": order["valid_until"],
                "custodian": self.config.handoff["交出方角色"],
                "fields": order["fields"]}

    def _manifest_diff(self, handoff):
        """对比移交时清单与案件当前材料（同一保全令字段范围），返回逐项差异。"""
        manifest = self.manifests[handoff["manifest_id"]]
        current = self._manifest_items(self.incidents[handoff["incident_id"]],
                                       set(manifest["fields"]))
        def norm(items):
            return {f"{i['category']}|{i['item_id']}": i["data"] for i in items}
        old, now = norm(manifest["items"]), norm(current)
        diffs = []
        for key in sorted(set(old) | set(now)):
            if key not in old:
                diffs.append({"item": key, "change": "added", "current": now[key]})
            elif key not in now:
                diffs.append({"item": key, "change": "removed", "previous": old[key]})
            elif old[key] != now[key]:
                diffs.append({"item": key, "change": "changed",
                              "previous": old[key], "current": now[key]})
        return diffs

    # ------------------------------------------------------------------ 移交
    def create_handoff(self, incident_id, payload, actor):
        """交出方按保全向外部机构移交；同（保全令+机构+用途）重复移交幂等。"""
        _require(actor, (self.config.handoff["交出方角色"],))
        inc = self._get_incident(incident_id)
        self._assert_not_merged(inc)
        order = self._order(payload.get("order_id"))
        if order["incident_id"] != incident_id:
            raise AppError("保全令不属于该事件")
        if order["status"] != "active":
            raise AppError("保全令未生效或已换版，不能据此移交")
        if self._parse_iso(order["valid_until"]) <= self._parse_iso(now_iso()):
            raise AppError("保全令授权期限已过，须经司法延期或重新签发后再移交", 409)
        receiver_org = payload.get("receiver_org")
        if not receiver_org:
            raise AppError("必须载明接收机构 receiver_org（来源与交出责任须可确认）")
        purpose = payload.get("purpose") or order["purpose"]
        if purpose != order["purpose"]:
            raise AppError("移交用途必须与保全令用途一致")

        self._assert_disclosure_open(inc)

        key = (order["order_id"], receiver_org, purpose)
        existing_id = self._handoff_keys.get(key)
        if existing_id:
            return self._handle_duplicate_handoff(self.handoffs[existing_id], key)

        self._assert_disclosure_authorized(inc)
        handoff_id = new_id("hd")
        at = now_iso()
        self._append("handoff_created", {
            "handoff_id": handoff_id, "incident_id": incident_id,
            "order_id": order["order_id"], "manifest_id": order["manifest_ids"][-1],
            "purpose": purpose, "receiver_org": receiver_org,
            "receiver_contact": payload.get("receiver_contact"),
            "handover_by": actor.get("name"), "at": at,
        })
        # 首次移交通知接收方；重复移交路径不会再发通知
        self._append("notification_sent", {
            "notif_id": new_id("ntf"), "incident_id": incident_id,
            "channel": "external_handoff", "to_role": self.config.handoff["接收方角色"],
            "reason": f"材料移交待接收签认：{self.config.purpose_name(purpose)}",
            "handoff_id": handoff_id, "at": at,
        })
        return {"duplicate": False, "handoff_id": handoff_id,
                "state": "pending_surrender", "manifest_id": order["manifest_ids"][-1]}

    def _handle_duplicate_handoff(self, handoff, key):
        """重复移交：不发通知、不生第二份清单；内容有变则开冲突复核。"""
        diffs = self._manifest_diff(handoff)
        if not diffs or handoff.get("conflict_accepted"):
            # 无差异，或差异已被复核裁定维持原清单：按幂等返回，不再重复开冲突/通知
            return {"duplicate": True, "handoff_id": handoff["handoff_id"],
                    "state": handoff["state"], "content_changed": False}
        open_conflict = next((c for c in self.conflicts.values()
                              if c["handoff_id"] == handoff["handoff_id"]
                              and c["status"] == "open"), None)
        if open_conflict:
            return {"duplicate": True, "handoff_id": handoff["handoff_id"],
                    "state": "conflict_review", "content_changed": True,
                    "conflict_id": open_conflict["conflict_id"]}
        conflict_id = new_id("cfl")
        self._append("handoff_conflict_raised", {
            "conflict_id": conflict_id, "handoff_id": handoff["handoff_id"],
            "incident_id": handoff["incident_id"], "differences": diffs,
            "duplicate_key": list(key), "at": now_iso(),
        })
        return {"duplicate": True, "handoff_id": handoff["handoff_id"],
                "state": "conflict_review", "content_changed": True,
                "conflict_id": conflict_id}

    def acknowledge_surrender(self, handoff_id, actor):
        """交出方签认：确认材料已按清单交出。"""
        _require(actor, (self.config.handoff["交出方角色"],))
        handoff = self._handoff(handoff_id)
        if handoff["state"] != "pending_surrender":
            raise AppError(f"当前状态 {handoff['state']} 不能再作出交出签认")
        self._append("handoff_surrender_acknowledged", {
            "handoff_id": handoff_id, "by": actor.get("name"),
            "role": actor["role"], "at": now_iso(),
        })
        return {"handoff_id": handoff_id, "state": "pending_receiver"}

    def acknowledge_handoff(self, handoff_id, actor, note=None):
        """接收方签认：确认收到且来源、责任、授权期限可确认。"""
        _require(actor, (self.config.handoff["接收方角色"],))
        handoff = self._handoff(handoff_id)
        if handoff["state"] not in ("pending_receiver",):
            raise AppError(f"当前状态 {handoff['state']} 不能作出接收签认")
        self._append("handoff_receiver_acknowledged", {
            "handoff_id": handoff_id, "by": actor.get("name"),
            "note": note, "at": now_iso(),
        })
        return {"handoff_id": handoff_id, "state": "acknowledged"}

    def reject_handoff(self, handoff_id, payload, actor):
        """接收方拒收：尚未接管材料即拒绝，只追加拒收事件。"""
        _require(actor, (self.config.handoff["接收方角色"],))
        handoff = self._handoff(handoff_id)
        if handoff["state"] != "pending_receiver":
            raise AppError(f"当前状态 {handoff['state']} 不能拒收")
        reason = self._validate_return_reason(payload)
        self._append("handoff_rejected", {
            "handoff_id": handoff_id, "reason": reason,
            "reason_name": self.config.return_reason_name(reason),
            "detail": payload.get("detail"), "items": payload.get("items", []),
            "partial": bool(payload.get("items")),
            "by": actor.get("name"), "at": now_iso(),
        })
        return {"handoff_id": handoff_id, "state": "rejected"}

    def return_handoff(self, handoff_id, payload, actor):
        """接收方接管后退回附件：不改写任何先前签认/回执，只追加退回事件。"""
        _require(actor, (self.config.handoff["接收方角色"],))
        handoff = self._handoff(handoff_id)
        if handoff["state"] != "acknowledged":
            raise AppError(f"当前状态 {handoff['state']} 不能退回（仅已签认接收的可退回）")
        reason = self._validate_return_reason(payload)
        self._append("handoff_returned", {
            "handoff_id": handoff_id, "reason": reason,
            "reason_name": self.config.return_reason_name(reason),
            "detail": payload.get("detail"), "items": payload.get("items", []),
            "partial": bool(payload.get("items")),
            "by": actor.get("name"), "at": now_iso(),
        })
        return {"handoff_id": handoff_id, "state": "returned"}

    def _validate_return_reason(self, payload):
        reason = payload.get("reason")
        if reason not in self.config.handoff_return_reasons:
            raise AppError(f"退回/拒收原因须为：{'、'.join(self.config.handoff_return_reasons)}")
        return reason

    def supplement_handoff(self, handoff_id, payload, actor):
        """退回/拒收后的补件：生成新清单作为后续事件，范围与期限受原保全令约束，须重新核权。"""
        _require(actor, (self.config.handoff["交出方角色"],))
        handoff = self._handoff(handoff_id)
        if handoff["state"] not in ("rejected", "returned",
                                    "conflict_review", "supplement_required"):
            raise AppError(f"当前状态 {handoff['state']} 不允许补件")
        order = self._order(handoff["order_id"])
        if order["status"] != "active":
            raise AppError("原保全令已失效，补件前须换版签发")
        if self._parse_iso(order["valid_until"]) <= self._parse_iso(now_iso()):
            raise AppError("保全令授权期限已过，须先司法延期再补件", 409)
        inc = self.incidents[handoff["incident_id"]]
        self._assert_disclosure_open(inc)
        self._assert_disclosure_authorized(inc)  # 新增披露重新核权

        new_manifest = self._generate_manifest(order["order_id"],
                                               supersedes_manifest=handoff["manifest_id"])
        self._append("handoff_supplemented", {
            "handoff_id": handoff_id, "manifest_id": new_manifest["manifest_id"],
            "previous_manifest_id": handoff["manifest_id"],
            "reason": payload.get("reason", "按退回意见补正材料"),
            "by": actor.get("name"), "at": now_iso(),
        })
        # 补件作为后续事件衔接：状态回到待接收签认，原签认与回执均保留
        # （投影由 _on_handoff_supplemented 经账本订阅更新）
        return {"handoff_id": handoff_id, "state": "pending_receiver",
                "manifest_id": new_manifest["manifest_id"],
                "manifest_sha256": new_manifest["manifest_sha256"]}

    def resolve_handoff_conflict(self, conflict_id, payload, actor):
        """冲突复核：维持原清单（重复移交结案）或要求补件换版。"""
        _require(actor, ("法务复核员", self.config.handoff["交出方角色"]))
        conflict = self.conflicts.get(conflict_id)
        if not conflict:
            raise AppError("冲突记录不存在", 404)
        if conflict["status"] != "open":
            raise AppError("该冲突已复核")
        decision = payload.get("decision")
        if decision not in ("accept_existing", "require_supplement"):
            raise AppError("decision 仅支持 accept_existing/require_supplement")
        self._append("handoff_conflict_resolved", {
            "conflict_id": conflict_id, "handoff_id": conflict["handoff_id"],
            "decision": decision, "note": payload.get("note"),
            "by": actor.get("name"), "at": now_iso(),
        })
        return {"conflict_id": conflict_id, "decision": decision}

    # ------------------------------------------------------------- 断点/查询
    def handoff_resume_point(self, handoff_id):
        """服务中断后从最后确认节点恢复：返回当前状态、最后账本序号与最后签认节点。"""
        handoff = self._handoff(handoff_id)
        last_confirmed = None
        if handoff["receiver_ack"]:
            last_confirmed = {"node": "receiver_acknowledged", **handoff["receiver_ack"]}
        elif handoff["surrender_ack"]:
            last_confirmed = {"node": "surrender_acknowledged", **handoff["surrender_ack"]}
        else:
            last_confirmed = {"node": "handoff_created", "at": handoff["created_at"]}
        return {"handoff_id": handoff_id, "state": handoff["state"],
                "last_event_seq": handoff["last_event_seq"],
                "ledger_last_seq": self._last_seq,
                "last_confirmed_node": last_confirmed}

    def handoff_view(self, handoff_id, as_role=None):
        handoff = self._handoff(handoff_id)
        order = self.orders[handoff["order_id"]]
        manifest = self.manifests[handoff["manifest_id"]]
        view = {
            "handoff_id": handoff_id, "incident_id": handoff["incident_id"],
            "state": handoff["state"], "purpose": handoff["purpose"],
            "purpose_name": self.config.purpose_name(handoff["purpose"]),
            "receiver_org": handoff["receiver_org"],
            "handover_by": handoff["handover_by"],
            "order": {"order_id": order["order_id"], "version": order["version"],
                      "valid_until": order["valid_until"], "extensions": order["extensions"]},
            "manifest_id": manifest["manifest_id"],
            "manifest_sha256": manifest["manifest_sha256"],
            "summary": manifest["summary"],
            "items": self._mask_items(manifest["items"], as_role),
            "surrender_ack": handoff["surrender_ack"],
            "receiver_ack": handoff["receiver_ack"],
            "rejection": handoff["rejection"],
            "returned": handoff["returned"],
            "supplement_of": handoff.get("supplement_of"),
            "event_chain": handoff["events"],
            "resume": self.handoff_resume_point(handoff_id),
        }
        return view

    def _mask_items(self, items, as_role):
        if as_role != "普通案件查看者":
            return items
        placeholder = self.config.handoff_mask_placeholder
        masked_fields = set(self.config.handoff_mask_fields)
        out = []
        for item in items:
            data = {k: (placeholder if k in masked_fields else v)
                    for k, v in item["data"].items()}
            out.append({"category": item["category"], "item_id": item["item_id"], "data": data})
        return out

    def list_handoffs(self, incident_id=None, state=None):
        out = []
        for handoff in self.handoffs.values():
            if incident_id and handoff["incident_id"] != incident_id:
                continue
            if state and handoff["state"] != state:
                continue
            out.append({"handoff_id": handoff["handoff_id"],
                        "incident_id": handoff["incident_id"],
                        "state": handoff["state"], "purpose": handoff["purpose"],
                        "order_id": handoff["order_id"],
                        "manifest_id": handoff["manifest_id"],
                        "receiver_org": handoff["receiver_org"]})
        return out

    def list_preservation_orders(self, incident_id=None):
        out = []
        for order in self.orders.values():
            if incident_id and order["incident_id"] != incident_id:
                continue
            out.append({"order_id": order["order_id"], "incident_id": order["incident_id"],
                        "version": order["version"], "status": order["status"],
                        "purpose": order["purpose"], "valid_until": order["valid_until"],
                        "superseded_by": order["superseded_by"],
                        "manifest_ids": order["manifest_ids"]})
        return out

    def case_traceability(self, incident_id, as_role=None):
        """案件追溯：逐项说明为何保全、由谁保管、何时到期、缺哪些外部回执；按角色脱敏。"""
        inc = self._get_incident(incident_id)
        viewer_limited = as_role == "普通案件查看者"
        placeholder = self.config.handoff_mask_placeholder
        material_index = {}
        for order_id in inc["preservation_orders"]:
            order = self.orders[order_id]
            seen_in_order = set()
            for manifest_id in order["manifest_ids"]:
                manifest = self.manifests[manifest_id]
                for item in manifest["items"]:
                    if item["category"] not in ("evidence", "account", "receipt"):
                        continue
                    key = f"{item['category']}|{item['item_id']}"
                    if key in seen_in_order:
                        continue
                    seen_in_order.add(key)
                    record = material_index.setdefault(key, {
                        "item": key, "category": item["category"],
                        "item_id": item["item_id"], "preserved_by_orders": []})
                    record["preserved_by_orders"].append({
                        "order_id": order_id, "version": order["version"],
                        "purpose": order["purpose"],
                        "purpose_name": self.config.purpose_name(order["purpose"]),
                        "why": f"依{order['version']}版保全令按"
                               f"{self.config.purpose_name(order['purpose'])}用途依法保全",
                        "custodian": self.config.handoff["交出方角色"],
                        "issued_by": order["issued_by"],
                        "valid_from": order["valid_from"],
                        "retention_until": order["valid_until"],
                        "extensions": order["extensions"],
                        "manifest_id": manifest_id,
                    })

        materials = list(material_index.values())
        for record in materials:
            record["retention_until"] = max(
                (o["retention_until"] for o in record["preserved_by_orders"]),
                default=None)
            if viewer_limited:
                record["item_id"] = placeholder

        external_followups = []
        missing_receipts = []
        for handoff_id in inc["handoffs"]:
            handoff = self.handoffs[handoff_id]
            external_followups.append({
                "handoff_id": handoff_id, "state": handoff["state"],
                "receiver_org": (placeholder if viewer_limited else handoff["receiver_org"]),
                "purpose": handoff["purpose"],
                "surrender_ack": handoff["surrender_ack"],
                "receiver_ack": (None if viewer_limited else handoff["receiver_ack"]),
                "rejection": handoff["rejection"], "returned": handoff["returned"],
            })
            if not handoff["receiver_ack"] and handoff["state"] not in ("rejected",):
                missing_receipts.append({
                    "handoff_id": handoff_id,
                    "missing": "receiver_acknowledgement",
                    "detail": f"接收机构 {handoff['receiver_org']} 尚未签认接收",
                    "state": handoff["state"]})
            open_conflicts = [c for c in self.conflicts.values()
                              if c["handoff_id"] == handoff_id and c["status"] == "open"]
            for conflict in open_conflicts:
                missing_receipts.append({
                    "handoff_id": handoff_id, "missing": "conflict_resolution",
                    "detail": f"冲突 {conflict['conflict_id']} 待复核",
                    "state": handoff["state"]})

        return {
            "incident_id": incident_id,
            "as_role": as_role,
            "masked": viewer_limited,
            "materials": materials,
            "external_followups": external_followups,
            "missing_external_receipts": missing_receipts,
            "minimal_retention_fields": self.config.handoff["最小保全字段"],
        }

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
            "外部移交保全": {
                "preservation_orders": [
                    {"order_id": self.orders[o]["order_id"],
                     "version": self.orders[o]["version"],
                     "status": self.orders[o]["status"],
                     "purpose": self.orders[o]["purpose"],
                     "valid_until": self.orders[o]["valid_until"]}
                    for o in inc["preservation_orders"]],
                "handoffs": [self.handoffs[h]["state"] for h in inc["handoffs"]],
                "handoff_ids": list(inc["handoffs"]),
            },
            "责任链": self._timeline(inc, mask),
        }
        if inc.get("closed_at"):
            digest["closed_at"] = inc["closed_at"]
            digest["close_reason"] = inc["close_reason"]
        return digest

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
