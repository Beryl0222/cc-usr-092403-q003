"""外部移交与法务保全令的全链路契约测试。

覆盖：
- 法务按案件+用途签发带版本/期限/字段范围的保全令，系统生成不可变清单与摘要；
- 交出方、接收方分别签认；拒收（含部分拒收）、退回、补件、司法延长只追加事件，
  不改写先前回执；
- 重复移交不发通知、不生第二份清单；内容变化进入冲突复核；
- 撤回对外披露授权后最小材料继续留存，新增披露（含补件）重新核权；
- 服务中断（JSONL 重放）从最后确认节点恢复；
- 案件逐项追溯（为何保全/谁保管/何时到期/缺失回执），普通查看者仅见脱敏内容。
"""

import json
import os
import tempfile
import threading
import unittest
from datetime import timedelta

from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app import AppError, CST, SafeguardingApp
from service import build_handler
from test_safeguarding import (
    AGENT, OFFICER, DUTY, LIASON, LEGAL, abuse_report, threat_report,
)

EXTERNAL = {"name": "外部调查员沈某", "role": "外部调查机构"}
VIEWER = {"name": "普通查看者", "role": "普通案件查看者"}

RECEIVER_ORG = "市公安局网安支队"


def future(days=30):
    from datetime import datetime
    return (datetime.now(CST) + timedelta(days=days)).isoformat(timespec="seconds")


def order_payload(**overrides):
    payload = {"purpose": "external_investigation", "valid_until": future()}
    payload.update(overrides)
    return payload


class PreservationOrderTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]

    def test_only_legal_can_issue_and_order_has_version_period_fields(self):
        with self.assertRaises(AppError) as ctx:
            self.app.issue_preservation_order(self.incident_id, order_payload(), OFFICER)
        self.assertEqual(ctx.exception.status, 403)

        result = self.app.issue_preservation_order(
            self.incident_id, order_payload(), LEGAL)
        self.assertEqual(result["version"], "v1")
        self.assertIn("evidence", result["field_groups"])
        self.assertTrue(result["manifest_sha256"])
        manifest = self.app.manifests[result["manifest_id"]]
        self.assertEqual(manifest["order_version"], "v1")
        self.assertEqual(manifest["summary"]["custodian"], "俱乐部保护专员")
        self.assertEqual(manifest["summary"]["retention_until"], result["valid_until"])
        # 摘要给出各类材料数量
        self.assertEqual(manifest["summary"]["material_counts"]["evidence"], 1)
        self.assertEqual(manifest["summary"]["material_counts"]["account"], 1)

    def test_order_requires_period_and_valid_period(self):
        with self.assertRaises(AppError):
            self.app.issue_preservation_order(
                self.incident_id, {"purpose": "external_investigation"}, LEGAL)
        with self.assertRaises(AppError):
            self.app.issue_preservation_order(self.incident_id, order_payload(
                valid_from=future(10), valid_until=future(1)), LEGAL)

    def test_field_scope_limits_manifest_fields_and_items(self):
        result = self.app.issue_preservation_order(
            self.incident_id, order_payload(field_groups=["evidence"]), LEGAL)
        manifest = self.app.manifests[result["manifest_id"]]
        self.assertTrue(manifest["items"])
        self.assertTrue(all(i["category"] == "evidence" for i in manifest["items"]))
        first = manifest["items"][0]["data"]
        self.assertIn("content_ref", first)
        # 字段仅限 evidence 分组：账号/回执/案件字段不出现
        self.assertNotIn("platform", first)
        self.assertNotIn("severity", first)
        # 账号与案件信息不在该字段范围内
        self.assertFalse(any(i["category"] in ("account", "case") for i in manifest["items"]))

    def test_versioning_requires_explicit_supersede(self):
        first = self.app.issue_preservation_order(
            self.incident_id, order_payload(), LEGAL)
        with self.assertRaises(AppError) as ctx:
            self.app.issue_preservation_order(self.incident_id, order_payload(
                valid_until=future(60)), LEGAL)
        self.assertEqual(ctx.exception.status, 409)
        second = self.app.issue_preservation_order(self.incident_id, order_payload(
            valid_until=future(60), supersedes=first["order_id"]), LEGAL)
        self.assertEqual(second["version"], "v2")
        self.assertEqual(self.app.orders[first["order_id"]]["status"], "superseded")
        self.assertEqual(self.app.orders[second["order_id"]]["status"], "active")
        # 两版清单均不可变留存
        self.assertIn(first["manifest_id"], self.app.manifests)
        self.assertNotEqual(first["manifest_id"], second["manifest_id"])

    def test_judicial_extension_appends_and_requires_legal_ref(self):
        order_id = self.app.issue_preservation_order(
            self.incident_id, order_payload(), LEGAL)["order_id"]
        with self.assertRaises(AppError):
            self.app.extend_preservation_order(
                order_id, {"new_valid_until": future(60)}, LEGAL)
        result = self.app.extend_preservation_order(order_id, {
            "new_valid_until": future(90), "legal_ref": "X法延字第2026-055号"}, LEGAL)
        self.assertTrue(result["valid_until"])
        order = self.app.orders[order_id]
        self.assertEqual(order["valid_until"], result["valid_until"])
        self.assertEqual(len(order["extensions"]), 1)
        self.assertEqual(order["extensions"][0]["legal_ref"], "X法延字第2026-055号")
        with self.assertRaises(AppError):  # 不能缩短
            self.app.extend_preservation_order(order_id, {
                "new_valid_until": future(1), "legal_ref": "X"}, LEGAL)


class HandoffSignoffTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        self.order_id = self.app.issue_preservation_order(
            self.incident_id, order_payload(), LEGAL)["order_id"]
        self.app.grant_consent(self.incident_id, ["external_disclosure"], AGENT)

    def _create(self):
        return self.app.create_handoff(self.incident_id, {
            "order_id": self.order_id, "receiver_org": RECEIVER_ORG}, OFFICER)

    def test_two_party_signoff_and_single_notification(self):
        created = self._create()
        self.assertFalse(created["duplicate"])
        handoff_id = created["handoff_id"]
        # 交出方先签认，接收方才能签认
        with self.assertRaises(AppError):
            self.app.acknowledge_handoff(handoff_id, EXTERNAL)
        self.assertEqual(self.app.acknowledge_surrender(handoff_id, OFFICER)["state"],
                         "pending_receiver")
        self.assertEqual(self.app.acknowledge_handoff(
            handoff_id, EXTERNAL, note="来源与期限可确认")["state"], "acknowledged")
        notifs = self.app.list_notifications(self.incident_id)
        handoff_notifs = [n for n in notifs if n["channel"] == "external_handoff"]
        self.assertEqual(len(handoff_notifs), 1)  # 仅首次移交通知一次

    def test_receiver_cannot_sign_before_custodian_and_roles_enforced(self):
        handoff_id = self._create()["handoff_id"]
        with self.assertRaises(AppError):
            self.app.acknowledge_surrender(handoff_id, EXTERNAL)
        with self.assertRaises(AppError):
            self.app.acknowledge_surrender(handoff_id, LEGAL)

    def test_handoff_requires_disclosure_consent_and_live_order(self):
        self.app.revoke_consent(self.incident_id, ["external_disclosure"], AGENT)
        with self.assertRaises(AppError) as ctx:
            self._create()
        self.assertEqual(ctx.exception.status, 409)
        self.app.grant_consent(self.incident_id, ["external_disclosure"], AGENT)
        self.assertFalse(self._create()["duplicate"])


class ReturnSupplementAndImmutabilityTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        self.order_id = self.app.issue_preservation_order(
            self.incident_id, order_payload(), LEGAL)["order_id"]
        self.app.grant_consent(self.incident_id, ["external_disclosure"], AGENT)
        self.handoff_id = self.app.create_handoff(self.incident_id, {
            "order_id": self.order_id, "receiver_org": RECEIVER_ORG}, OFFICER)["handoff_id"]
        self.app.acknowledge_surrender(self.handoff_id, OFFICER)

    def test_partial_rejection_then_supplement_keeps_prior_receipts(self):
        original_manifest = self.app.handoffs[self.handoff_id]["manifest_id"]
        rejected = self.app.reject_handoff(self.handoff_id, {
            "reason": "source_unconfirmed",
            "detail": "3 个附件来源无法确认",
            "items": ["ev_supplement_01", "ev_supplement_02"]}, EXTERNAL)
        self.assertEqual(rejected["state"], "rejected")

        # 撤回非核心授权后，补件属新增披露，必须重新核权
        self.app.revoke_consent(self.incident_id, ["external_disclosure"], AGENT)
        with self.assertRaises(AppError) as ctx:
            self.app.supplement_handoff(self.handoff_id, {"reason": "补正来源说明"}, OFFICER)
        self.assertEqual(ctx.exception.status, 409)
        self.app.grant_consent(self.incident_id, ["external_disclosure"], AGENT)

        supplemented = self.app.supplement_handoff(
            self.handoff_id, {"reason": "补正来源与授权期限"}, OFFICER)
        self.assertEqual(supplemented["state"], "pending_receiver")
        self.assertNotEqual(supplemented["manifest_id"], original_manifest)
        # 原清单不可变，仍可查
        self.assertIn(original_manifest, self.app.manifests)
        # 拒收记录作为后续事件保留；接收方可以再次签认
        view = self.app.handoff_view(self.handoff_id)
        self.assertEqual(view["rejection"]["reason"], "source_unconfirmed")
        self.assertEqual(view["rejection"]["items"], ["ev_supplement_01", "ev_supplement_02"])
        self.assertEqual(self.app.acknowledge_handoff(self.handoff_id, EXTERNAL)["state"],
                         "acknowledged")

    def test_return_after_ack_does_not_rewrite_prior_acknowledgement(self):
        self.app.acknowledge_handoff(self.handoff_id, EXTERNAL, note="已接收")
        first_ack = dict(self.app.handoffs[self.handoff_id]["receiver_ack"])
        self.app.return_handoff(self.handoff_id, {
            "reason": "authorization_expired",
            "detail": "2 个附件无授权期限", "items": ["ev_x"]}, EXTERNAL)
        handoff = self.app.handoffs[self.handoff_id]
        self.assertEqual(handoff["state"], "returned")
        # 先前接收签认回执原样保留，未被退回改写
        self.assertEqual(handoff["receiver_ack"], first_ack)
        self.assertTrue(handoff["returned"]["items"])
        # 补件衔接为后续事件，不再发第二次移交通知
        before = len([n for n in self.app.list_notifications(self.incident_id)
                      if n["channel"] == "external_handoff"])
        self.app.supplement_handoff(self.handoff_id, {"reason": "补齐授权期限"}, OFFICER)
        after = len([n for n in self.app.list_notifications(self.incident_id)
                     if n["channel"] == "external_handoff"])
        self.assertEqual(before, after)


class DuplicateAndConflictTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        self.order_id = self.app.issue_preservation_order(
            self.incident_id, order_payload(), LEGAL)["order_id"]
        self.app.grant_consent(self.incident_id, ["external_disclosure"], AGENT)

    def _handoff_args(self):
        return {"order_id": self.order_id, "receiver_org": RECEIVER_ORG}

    def test_duplicate_handoff_is_idempotent_without_notice_or_second_manifest(self):
        first = self.app.create_handoff(self.incident_id, self._handoff_args(), OFFICER)
        manifests_before = len(self.app.manifests)
        notifs_before = len(self.app.list_notifications())
        second = self.app.create_handoff(self.incident_id, self._handoff_args(), OFFICER)
        self.assertTrue(second["duplicate"])
        self.assertFalse(second["content_changed"])
        self.assertEqual(second["handoff_id"], first["handoff_id"])
        self.assertEqual(len(self.app.manifests), manifests_before)
        self.assertEqual(len(self.app.list_notifications()), notifs_before)
        self.assertEqual(len(self.app.list_handoffs()), 1)  # 没有第二份移交

    def test_content_change_routes_duplicate_into_conflict_review(self):
        handoff_id = self.app.create_handoff(
            self.incident_id, self._handoff_args(), OFFICER)["handoff_id"]
        self.app.acknowledge_surrender(handoff_id, OFFICER)
        self.app.acknowledge_handoff(handoff_id, EXTERNAL)

        # 案件材料在移交后变化：平台回调告知账号改名（改名只追加，不抹旧名）
        self.app.platform_callback({
            "callback_id": "CB-RENAME", "incident_id": self.incident_id,
            "account": {"platform": "douyin", "account_key": "dy_hater_9",
                        "display_name": "改名后的账号名"}})

        dup = self.app.create_handoff(self.incident_id, self._handoff_args(), OFFICER)
        self.assertTrue(dup["duplicate"])
        self.assertTrue(dup["content_changed"])
        self.assertEqual(dup["state"], "conflict_review")
        conflict_id = dup["conflict_id"]
        conflict = self.app.conflicts[conflict_id]
        self.assertTrue(any(d["change"] == "changed" for d in conflict["differences"]))
        # 重复移交期间仍只有首次通知
        self.assertEqual(len([n for n in self.app.list_notifications()
                              if n["channel"] == "external_handoff"]), 1)

        # 法务裁定维持原清单：之后重复移交按幂等处理，不再重复开冲突
        self.app.resolve_handoff_conflict(conflict_id, {"decision": "accept_existing"}, LEGAL)
        again = self.app.create_handoff(self.incident_id, self._handoff_args(), OFFICER)
        self.assertTrue(again["duplicate"])
        self.assertFalse(again["content_changed"])

    def test_conflict_require_supplement_allows_new_manifest(self):
        handoff_id = self.app.create_handoff(
            self.incident_id, self._handoff_args(), OFFICER)["handoff_id"]
        self.app.acknowledge_surrender(handoff_id, OFFICER)
        self.app.add_evidence(self.incident_id,
                              {"content_ref": "https://video.example/comment/99"}, OFFICER)
        conflict_id = self.app.create_handoff(
            self.incident_id, self._handoff_args(), OFFICER)["conflict_id"]
        self.app.resolve_handoff_conflict(
            conflict_id, {"decision": "require_supplement"}, LEGAL)
        self.assertEqual(self.app.handoffs[handoff_id]["state"], "supplement_required")
        result = self.app.supplement_handoff(handoff_id, {"reason": "并入新证据"}, OFFICER)
        self.assertEqual(result["state"], "pending_receiver")


class RetentionAndReauthorizationTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        self.order_id = self.app.issue_preservation_order(
            self.incident_id, order_payload(), LEGAL)["order_id"]
        self.app.grant_consent(self.incident_id, ["external_disclosure"], AGENT)
        self.handoff_id = self.app.create_handoff(self.incident_id, {
            "order_id": self.order_id, "receiver_org": RECEIVER_ORG}, OFFICER)["handoff_id"]

    def test_minimal_material_survives_revocation_but_new_disclosure_needs_reauth(self):
        self.app.revoke_consent(self.incident_id, ["external_disclosure"], AGENT)
        # 已依法保全的最小材料继续留存：保全令、清单、追溯均可查
        trace = self.app.case_traceability(self.incident_id)
        self.assertTrue(trace["materials"])
        self.assertTrue(all(
            m["preserved_by_orders"][0]["retention_until"] for m in trace["materials"]))
        self.assertEqual(self.app.orders[self.order_id]["status"], "active")
        # 任何新增披露被阻断
        with self.assertRaises(AppError) as ctx:
            self.app.create_handoff(self.incident_id, {
                "order_id": self.order_id, "receiver_org": "另一机构"}, OFFICER)
        self.assertEqual(ctx.exception.status, 409)
        # 重新核权后新增披露放行
        self.app.grant_consent(self.incident_id, ["external_disclosure"], AGENT)
        second = self.app.create_handoff(self.incident_id, {
            "order_id": self.order_id, "receiver_org": "另一机构"}, OFFICER)
        self.assertFalse(second["duplicate"])


class TraceabilityAndMaskingTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        self.order_id = self.app.issue_preservation_order(
            self.incident_id, order_payload(), LEGAL)["order_id"]
        self.app.grant_consent(self.incident_id, ["external_disclosure"], AGENT)

    def test_trace_explains_each_material_and_flags_missing_receipts(self):
        handoff_id = self.app.create_handoff(self.incident_id, {
            "order_id": self.order_id, "receiver_org": RECEIVER_ORG}, OFFICER)["handoff_id"]
        # 尚未接收签认：追溯应指出外部回执缺失
        trace = self.app.case_traceability(self.incident_id, as_role="法务复核员")
        self.assertTrue(trace["materials"])
        first = trace["materials"][0]["preserved_by_orders"][0]
        self.assertTrue(first["why"])
        self.assertEqual(first["custodian"], "俱乐部保护专员")
        self.assertTrue(first["retention_until"])
        missing = {m["missing"] for m in trace["missing_external_receipts"]}
        self.assertIn("receiver_acknowledgement", missing)

        self.app.acknowledge_surrender(handoff_id, OFFICER)
        self.app.acknowledge_handoff(handoff_id, EXTERNAL)
        trace = self.app.case_traceability(self.incident_id, as_role="法务复核员")
        self.assertEqual(trace["missing_external_receipts"], [])

    def test_general_viewer_only_gets_masked_content(self):
        handoff_id = self.app.create_handoff(self.incident_id, {
            "order_id": self.order_id, "receiver_org": RECEIVER_ORG}, OFFICER)["handoff_id"]
        self.app.acknowledge_surrender(handoff_id, OFFICER)
        self.app.acknowledge_handoff(handoff_id, EXTERNAL)

        public_view = self.app.handoff_view(handoff_id, as_role="普通案件查看者")
        flat = {k: v for item in public_view["items"] for k, v in item["data"].items()}
        self.assertNotIn("https://video.example/comment/55", flat.values())
        self.assertNotIn("dy_hater_9", flat.values())
        self.assertIn("【无权查看】", flat.values())

        trace = self.app.case_traceability(self.incident_id, as_role="普通案件查看者")
        self.assertTrue(trace["masked"])
        self.assertTrue(all(m["item_id"] == "【无权查看】" for m in trace["materials"]))
        self.assertTrue(all(f["receiver_org"] == "【无权查看】"
                            for f in trace["external_followups"]))
        self.assertTrue(all(f["receiver_ack"] is None for f in trace["external_followups"]))

        # 有权角色看到明文
        legal_view = self.app.handoff_view(handoff_id, as_role="法务复核员")
        flat_legal = {k: v for item in legal_view["items"] for k, v in item["data"].items()}
        self.assertIn("https://video.example/comment/55", flat_legal.values())


class ResumeAndPersistenceTest(unittest.TestCase):
    def _run_flow(self, app):
        incident_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
        order_id = app.issue_preservation_order(
            incident_id, order_payload(), LEGAL)["order_id"]
        app.grant_consent(incident_id, ["external_disclosure"], AGENT)
        handoff_id = app.create_handoff(incident_id, {
            "order_id": order_id, "receiver_org": RECEIVER_ORG}, OFFICER)["handoff_id"]
        app.acknowledge_surrender(handoff_id, OFFICER)
        app.acknowledge_handoff(handoff_id, EXTERNAL)
        return incident_id, order_id, handoff_id

    def test_resume_reports_last_confirmed_node(self):
        app = SafeguardingApp()
        incident_id, _order_id, handoff_id = self._run_flow(app)
        resume = app.handoff_resume_point(handoff_id)
        self.assertEqual(resume["state"], "acknowledged")
        self.assertEqual(resume["last_confirmed_node"]["node"], "receiver_acknowledged")
        self.assertLessEqual(resume["last_event_seq"], resume["ledger_last_seq"])

    def test_ledger_replay_resumes_handoff_and_keeps_dedup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            app = SafeguardingApp(store_path=path)
            incident_id, order_id, handoff_id = self._run_flow(app)
            seq_before = app.handoff_resume_point(handoff_id)["last_event_seq"]

            reloaded = SafeguardingApp(store_path=path)
            self.assertEqual(reloaded.handoffs[handoff_id]["state"], "acknowledged")
            resume = reloaded.handoff_resume_point(handoff_id)
            self.assertEqual(resume["last_confirmed_node"]["node"], "receiver_acknowledged")
            self.assertEqual(resume["last_event_seq"], seq_before)
            # 重放后重复移交仍幂等，不发通知、不生第二份清单
            dup = reloaded.create_handoff(incident_id, {
                "order_id": order_id, "receiver_org": RECEIVER_ORG}, OFFICER)
            self.assertTrue(dup["duplicate"])
            self.assertEqual(len(reloaded.list_handoffs()), 1)
            self.assertEqual(len([n for n in reloaded.list_notifications()
                                  if n["channel"] == "external_handoff"]), 1)


class HandoffHttpContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = SafeguardingApp()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.app))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _request(self, method, path, payload=None):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        request = Request(f"{self.base_url}{path}", data=data, method=method,
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def test_handoff_lifecycle_over_http(self):
        # 立案 + 核权
        status, body = self._request("POST", "/reports", abuse_report(actor=AGENT))
        incident_id = body["incident_id"]
        self.assertEqual(status, 201)
        self._request("POST", f"/incidents/{incident_id}/consent/grant",
                      {"actor": AGENT, "scopes": ["external_disclosure"]})

        # 法务签发保全令
        status, order = self._request(
            "POST", f"/incidents/{incident_id}/preservation-orders",
            {"actor": LEGAL, "purpose": "external_investigation", "valid_until": future()})
        self.assertEqual(status, 201)
        order_id, manifest_id = order["order_id"], order["manifest_id"]

        # 保护专员（交出方）移交
        status, created = self._request("POST", f"/incidents/{incident_id}/handoffs",
                                        {"actor": OFFICER, "order_id": order_id,
                                         "receiver_org": RECEIVER_ORG})
        self.assertEqual(status, 201)
        handoff_id = created["handoff_id"]

        # 双方分别签认
        self.assertEqual(self._request("POST", f"/handoffs/{handoff_id}/surrender-ack",
                                       {"actor": OFFICER})[0], 200)
        self.assertEqual(self._request("POST", f"/handoffs/{handoff_id}/receiver-ack",
                                       {"actor": EXTERNAL, "note": "ok"})[0], 200)

        # 追溯（普通查看者脱敏）
        status, trace = self._request(
            "GET", f"/incidents/{incident_id}/traceability?as_role="
                   + quote("普通案件查看者"))
        self.assertEqual(status, 200)
        self.assertTrue(trace["masked"])
        self.assertTrue(all(m["item_id"] == "【无权查看】" for m in trace["materials"]))

        # 移交详情断点节点
        status, detail = self._request("GET", f"/handoffs/{handoff_id}")
        self.assertEqual(status, 200)
        self.assertEqual(detail["resume"]["last_confirmed_node"]["node"],
                         "receiver_acknowledged")
        self.assertEqual(detail["manifest_id"], manifest_id)

        # 重复移交幂等
        status, dup = self._request("POST", f"/incidents/{incident_id}/handoffs",
                                    {"actor": OFFICER, "order_id": order_id,
                                     "receiver_org": RECEIVER_ORG})
        self.assertTrue(dup["duplicate"])


if __name__ == "__main__":
    unittest.main()
