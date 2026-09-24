"""材料保全移交（外部调查机构）全链路契约测试。

覆盖：
- 法务按案件/用途签发带版本、期限、字段范围的保全令，系统固化不可变清单与摘要；
- 交出方/接收方分别签认，签认回执不可改写；
- 部分拒收、整批退回、补件（新增披露重新核权）、司法延长只追加衔接事件；
- 重复移交不通知、不生成第二份清单，内容变化进入冲突复核；
- 依法最小材料在授权撤回后继续留存；
- 服务中断后从最后确认节点重放恢复；
- 案件追溯逐项说明为何保全/保管方/到期/缺失外部回执；普通查看者只见脱敏内容。
"""

import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app import AppError, SafeguardingApp
from service import build_handler
from test_safeguarding import AGENT, OFFICER, DUTY, LEGAL, threat_report, abuse_report

EXTERNAL = {"name": "调查员李征", "role": "外部调查机构"}
VIEWER = {"name": "查看员小柯", "role": "普通案件查看者"}

CASE_FIELDS = ["victim_code", "content_ref", "content_sha256",
               "linked_accounts", "platform_receipts", "action_chain"]
RECEIVER = {"org_code": "INV-9", "org_name": "某外部调查机构"}


def open_threat_case(app):
    incident_id = app.submit_report(threat_report(), AGENT)["incident_id"]
    app.acknowledge_escalation(incident_id, DUTY)
    return incident_id


class PreservationOrderIssueTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = open_threat_case(self.app)

    def _issue(self, **overrides):
        payload = {
            "case_no": "CASE-2026-001", "purpose": "external_investigation",
            "receiver": dict(RECEIVER), "field_scope": list(CASE_FIELDS),
            "expected_receipts": [
                {"receipt_id": "WB-2026-09-18-7781", "platform": "weibo"}],
        }
        payload.update(overrides)
        return self.app.issue_preservation_order(self.incident_id, payload, LEGAL)

    def test_only_legal_can_issue_and_requires_scope_and_receiver(self):
        with self.assertRaises(AppError) as ctx:
            self.app.issue_preservation_order(
                self.incident_id, {"purpose": "external_investigation",
                                   "receiver": RECEIVER, "field_scope": ["victim_code"]},
                OFFICER)
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(AppError):
            self._issue(receiver={"org_code": ""})
        with self.assertRaises(AppError):
            self._issue(field_scope=[])
        with self.assertRaises(AppError):
            self._issue(purpose="unknown_purpose")
        with self.assertRaises(AppError):
            self._issue(field_scope=["victim_code", "no_such_field"])

    def test_manifest_is_immutable_with_version_deadline_and_digest(self):
        result = self._issue()
        self.assertEqual(result["version"], 1)
        self.assertFalse(result["duplicate"])
        order = self.app.preservation_orders[result["order_id"]]
        self.assertIn("T", order["expires_at"])
        self.assertEqual(order["field_scope"], CASE_FIELDS)
        manifest = self.app.manifests[result["manifest_id"]]
        self.assertEqual(manifest["order_version"], 1)
        self.assertTrue(manifest["digest"])
        codes = [i["field_code"] for i in manifest["items"]]
        self.assertEqual(codes, CASE_FIELDS)
        # 摘要逐项哈希可独立校验
        for item in manifest["items"]:
            self.assertTrue(item["item_sha256"])

    def test_judicial_transfer_must_include_minimal_fields(self):
        with self.assertRaises(AppError):
            self._issue(purpose="judicial_transfer",
                        field_scope=["platform_receipts"])
        result = self._issue(purpose="judicial_transfer",
                             field_scope=["victim_code", "content_ref", "content_sha256"])
        self.assertEqual(result["version"], 1)


class DualAckAndFollowupTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = open_threat_case(self.app)
        self.order = self.app.issue_preservation_order(self.incident_id, {
            "case_no": "CASE-1", "purpose": "external_investigation",
            "receiver": dict(RECEIVER), "field_scope": list(CASE_FIELDS)}, LEGAL)
        self.manifest_id = self.order["manifest_id"]

    def test_two_parties_ack_separately_and_ack_is_immutable(self):
        r1 = self.app.acknowledge_manifest(self.manifest_id, OFFICER, note="交出方核对")
        self.assertEqual(r1["party"], "surrender")
        self.assertEqual(r1["status"], "pending_ack")
        r2 = self.app.acknowledge_manifest(self.manifest_id, EXTERNAL, note="接收方收讫")
        self.assertEqual(r2["party"], "receiver")
        self.assertEqual(r2["status"], "acknowledged")
        # 已签认方不能改写先前回执
        with self.assertRaises(AppError):
            self.app.acknowledge_manifest(self.manifest_id, OFFICER)
        with self.assertRaises(AppError):
            self.app.acknowledge_manifest(self.manifest_id, EXTERNAL)
        # 非移交双方不能签认
        with self.assertRaises(AppError) as ctx:
            self.app.acknowledge_manifest(self.manifest_id, AGENT)
        self.assertEqual(ctx.exception.status, 403)

    def test_partial_rejection_appends_without_rewriting_manifest(self):
        self.app.acknowledge_manifest(self.manifest_id, OFFICER)
        before_digest = self.app.manifests[self.manifest_id]["digest"]
        self.app.reject_manifest_items(
            self.manifest_id, ["platform_receipts"], "来源无法确认", EXTERNAL)
        manifest = self.app.manifests[self.manifest_id]
        self.assertEqual(manifest["status"], "partial_rejection")
        self.assertEqual(manifest["digest"], before_digest)  # 清单本体不改写
        kinds = [e["kind"] for e in manifest["events"]]
        self.assertIn("partial_rejection", kinds)
        # 签认回执仍在
        self.assertIsNotNone(manifest["surrender_ack"])

    def test_return_requires_valid_reason_and_is_append_only(self):
        with self.assertRaises(AppError):
            self.app.return_manifest(self.manifest_id, "瞎写的原因", EXTERNAL)
        result = self.app.return_manifest(self.manifest_id, "授权期限不明", EXTERNAL)
        self.assertEqual(result["status"], "returned")
        with self.assertRaises(AppError):
            self.app.acknowledge_manifest(self.manifest_id, EXTERNAL)
        # 整批退回后不能在原清单上补件，须重新签发保全令
        with self.assertRaises(AppError) as ctx:
            self.app.supplement_manifest(self.manifest_id, ["platform_receipts"], OFFICER)
        self.assertEqual(ctx.exception.status, 409)

    def test_supplement_within_scope_appends_but_new_disclosure_beyond_scope_reauthorized(self):
        # 超出原披露字段：任何新增披露必须重新核权、签发新版本，不在原清单上扩字段
        with self.assertRaises(AppError) as ctx:
            self.app.supplement_manifest(self.manifest_id, ["raw_contact"], OFFICER)
        self.assertEqual(ctx.exception.status, 409)

        # 当事人撤回非核心授权（公开澄清）：依法保全的最小材料继续留存，
        # 不影响在保全令字段范围内的补件，原清单与签认仍不改写
        scopes = self.app.revoke_consent(self.incident_id, ["public_statement"], AGENT)
        self.assertNotIn("public_statement", scopes)
        before_digest = self.app.manifests[self.manifest_id]["digest"]
        result = self.app.supplement_manifest(
            self.manifest_id, ["platform_receipts"], OFFICER, note="补平台回执引用")
        self.assertIn("supplemented_fields", result)
        self.assertEqual(self.app.manifests[self.manifest_id]["digest"], before_digest)
        kinds = [e["kind"] for e in self.app.manifests[self.manifest_id]["events"]]
        self.assertEqual(kinds.count("supplemented"), 1)
        # 最小材料仍可追溯
        trace = self.app.case_trace(self.incident_id, as_role=LEGAL["role"])
        minimal = {i["field_code"] for i in trace["preservation_orders"][0]["items"]
                   if i["minimal"]}
        self.assertEqual(minimal, {"victim_code", "content_ref", "content_sha256"})


class RepeatHandoffAndConflictTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = open_threat_case(self.app)
        self.payload = {
            "case_no": "CASE-9", "purpose": "external_investigation",
            "receiver": dict(RECEIVER),
            "field_scope": ["victim_code", "content_ref", "content_sha256"]}
        self.first = self.app.issue_preservation_order(
            self.incident_id, self.payload, LEGAL)

    def test_identical_repeat_is_idempotent_no_notification_no_second_manifest(self):
        # 首次移交产生签认通知
        first_notifs = len(self.app.list_notifications(self.incident_id))
        self.assertGreater(first_notifs, 0)
        repeat = self.app.issue_preservation_order(
            self.incident_id, json.loads(json.dumps(self.payload)), LEGAL)
        self.assertTrue(repeat["duplicate"])
        self.assertEqual(repeat["manifest_id"], self.first["manifest_id"])
        self.assertEqual(len(self.app.list_notifications(self.incident_id)), first_notifs)
        self.assertEqual(
            len([m for m in self.app.manifests.values()]), 1)

    def test_changed_content_raises_conflict_instead_of_second_manifest(self):
        self.app.add_evidence(self.incident_id,
                              {"content_ref": "https://weibo.example/comment/9999"}, AGENT)
        repeat = self.app.issue_preservation_order(
            self.incident_id, json.loads(json.dumps(self.payload)), LEGAL)
        self.assertTrue(repeat["duplicate"])
        self.assertIn("conflict_id", repeat)
        # 仍只有一份清单，且没有新增通知
        self.assertEqual(len(self.app.manifests), 1)
        conflicts = self.app.list_conflicts()
        self.assertEqual(len(conflicts), 1)
        self.assertTrue(any("内容已变化" in d for d in conflicts[0]["differences"]))

        resolved = self.app.resolve_handoff_conflict(
            repeat["conflict_id"], "issue_new_version", LEGAL, note="确认补证需更新披露")
        new_order_id = resolved["new_order_id"]
        self.assertIsNotNone(new_order_id)
        new_order = self.app.preservation_orders[new_order_id]
        self.assertEqual(new_order["version"], 2)
        self.assertEqual(new_order["supersedes"], self.first["order_id"])
        self.assertEqual(
            self.app.preservation_orders[self.first["order_id"]]["status"], "superseded")
        # 新版本生成新清单，但旧清单原样保留
        self.assertEqual(len(self.app.manifests), 2)
        self.assertNotEqual(new_order["manifest_id"], self.first["manifest_id"])

    def test_keep_existing_resolves_conflict_without_new_version(self):
        self.app.add_evidence(self.incident_id,
                              {"content_ref": "https://weibo.example/comment/8888"}, AGENT)
        repeat = self.app.issue_preservation_order(
            self.incident_id, json.loads(json.dumps(self.payload)), LEGAL)
        resolved = self.app.resolve_handoff_conflict(
            repeat["conflict_id"], "keep_existing", OFFICER)
        self.assertIsNone(resolved["new_order_id"])
        self.assertEqual(len(self.app.manifests), 1)
        self.assertEqual(self.app.list_conflicts(status="open"), [])


class ExtensionAndRetentionTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = open_threat_case(self.app)

    def test_judicial_extension_is_appended_only(self):
        order = self.app.issue_preservation_order(self.incident_id, {
            "case_no": "CASE-J", "purpose": "judicial_transfer",
            "receiver": dict(RECEIVER),
            "field_scope": ["victim_code", "content_ref", "content_sha256"]}, LEGAL)
        order_id = order["order_id"]
        original_expiry = self.app.preservation_orders[order_id]["expires_at"]
        result = self.app.extend_preservation(
            order_id, LEGAL, "司法程序延长保全期", duration_days=60)
        self.assertTrue(result["judicial"])
        self.assertNotEqual(result["expires_at"], original_expiry)
        order_view = self.app.preservation_orders[order_id]
        self.assertEqual(len(order_view["extensions"]), 1)
        self.assertEqual(order_view["extensions"][0]["previous_expires_at"], original_expiry)
        self.assertEqual(order_view["expires_at"], result["expires_at"])
        # 非司法理由不打 judicial 标记
        result2 = self.app.extend_preservation(
            order_id, LEGAL, "调查需要继续保管", duration_days=10)
        self.assertFalse(result2["judicial"])
        self.assertEqual(len(order_view["extensions"]), 2)

    def test_minimal_material_retained_when_non_core_consent_revoked(self):
        self.app.issue_preservation_order(self.incident_id, {
            "case_no": "CASE-M", "purpose": "external_investigation",
            "receiver": dict(RECEIVER),
            "field_scope": ["victim_code", "content_ref", "content_sha256"]}, LEGAL)
        # 非核心授权（公开澄清）可撤回
        scopes = self.app.revoke_consent(self.incident_id, ["public_statement"], AGENT)
        self.assertNotIn("public_statement", scopes)
        # 证据留存授权因依法保全令存续不可撤回
        with self.assertRaises(AppError):
            self.app.revoke_consent(self.incident_id, ["evidence_storage"], AGENT)
        # 最小材料仍在，且记录未被抹除
        trace = self.app.case_trace(self.incident_id, as_role=LEGAL["role"])
        order0 = trace["preservation_orders"][0]
        minimal_items = [i for i in order0["items"] if i["minimal"]]
        self.assertEqual({i["field_code"] for i in minimal_items},
                         {"victim_code", "content_ref", "content_sha256"})
        self.assertTrue(all(i["present"] for i in minimal_items))


class CaseTraceAndMaskingTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        self.order = self.app.issue_preservation_order(self.incident_id, {
            "case_no": "CASE-T", "purpose": "external_investigation",
            "receiver": dict(RECEIVER), "field_scope": list(CASE_FIELDS),
            "expected_receipts": [
                {"receipt_id": "DY-8840217", "platform": "douyin"},
                {"receipt_id": "DY-MISSING", "platform": "douyin"}]}, LEGAL)
        # 平台只回来一张回执，另一张缺失
        self.app.platform_callback({
            "callback_id": "CB-TRACE", "incident_id": self.incident_id,
            "receipt": {"receipt_id": "DY-8840217", "platform": "douyin",
                        "status": "accepted"}})
        self.manifest_id = self.order["manifest_id"]
        self.app.acknowledge_manifest(self.manifest_id, OFFICER)
        self.app.acknowledge_manifest(self.manifest_id, EXTERNAL)

    def test_trace_explains_each_item_why_custodian_expiry_and_missing_receipts(self):
        trace = self.app.case_trace(self.incident_id, as_role=LEGAL["role"])
        self.assertEqual(trace["case_no"], "CASE-T")
        order0 = trace["preservation_orders"][0]
        self.assertTrue(order0["expires_at"])
        self.assertIn("接收方", order0["custodian"])  # 双方已签认，由接收方保管
        missing = order0["missing_external_receipts"]
        self.assertEqual([m["receipt_id"] for m in missing], ["DY-MISSING"])
        # 收到的回执不在缺失清单
        self.assertNotIn("DY-8840217", [m["receipt_id"] for m in missing])
        for item in order0["items"]:
            self.assertTrue(item["why_preserved"])
            self.assertEqual(item["expires_at"], order0["expires_at"])
            self.assertTrue(item["custodian"])
        # 双方签认均可追溯
        self.assertEqual(order0["surrender_ack"]["by"], OFFICER["name"])
        self.assertEqual(order0["receiver_ack"]["by"], EXTERNAL["name"])

    def test_general_viewer_only_gets_masked_content(self):
        trace = self.app.case_trace(self.incident_id, as_role=VIEWER["role"])
        self.assertTrue(trace["masked"])
        order0 = trace["preservation_orders"][0]
        # 元信息可见
        self.assertEqual(order0["case_no"], "CASE-T")
        self.assertEqual(order0["manifest_status"], "acknowledged")
        # 机构被掩码
        self.assertEqual(order0["receiver"]["org_code"], "****")
        values = {i["field_code"]: i["value"] for i in order0["items"]}
        self.assertEqual(values["victim_code"], "****")
        self.assertTrue(all(v == "****" for v in values["content_ref"]))
        self.assertTrue(all(v == "****" for v in values["content_sha256"]) is False)  # 哈希不在脱敏字段
        # 清单视图同样脱敏
        masked_manifest = self.app.get_manifest(self.manifest_id, as_role=VIEWER["role"])
        victim = next(i for i in masked_manifest["items"] if i["field_code"] == "victim_code")
        self.assertEqual(victim["value"], "****")
        # 法务视图不脱敏
        legal_manifest = self.app.get_manifest(self.manifest_id, as_role=LEGAL["role"])
        victim_legal = next(i for i in legal_manifest["items"]
                            if i["field_code"] == "victim_code")
        self.assertEqual(victim_legal["value"], "ATH-009")


class PreservationPersistenceTest(unittest.TestCase):
    def test_replay_resumes_from_last_confirmed_node(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "preservation.jsonl")
            app = SafeguardingApp(store_path=path)
            incident_id = open_threat_case(app)
            order = app.issue_preservation_order(incident_id, {
                "case_no": "CASE-P", "purpose": "external_investigation",
                "receiver": dict(RECEIVER),
                "field_scope": ["victim_code", "content_ref", "content_sha256"]}, LEGAL)
            app.acknowledge_manifest(order["manifest_id"], OFFICER)
            app.reject_manifest_items(
                order["manifest_id"], ["content_ref"], "来源无法确认", EXTERNAL)

            # 服务中断后重建：从最后确认节点（已签认/已拒收）恢复，不补做任何动作
            reloaded = SafeguardingApp(store_path=path)
            manifest = reloaded.manifests[order["manifest_id"]]
            self.assertEqual(manifest["surrender_ack"]["by"], OFFICER["name"])
            self.assertIsNone(manifest["receiver_ack"])
            self.assertEqual(manifest["status"], "partial_rejection")
            kinds = [e["kind"] for e in manifest["events"]]
            self.assertEqual(kinds, ["partial_rejection"])
            restored_order = reloaded.preservation_orders[order["order_id"]]
            self.assertEqual(restored_order["version"], 1)
            # 重复移交幂等索引在重放后仍有效
            repeat = reloaded.issue_preservation_order(incident_id, {
                "case_no": "CASE-P", "purpose": "external_investigation",
                "receiver": dict(RECEIVER),
                "field_scope": ["victim_code", "content_ref", "content_sha256"]}, LEGAL)
            self.assertTrue(repeat["duplicate"])
            self.assertEqual(len(reloaded.manifests), 1)


class PreservationHttpTest(unittest.TestCase):
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

    def test_preservation_flow_over_http(self):
        incident_id = open_threat_case(self.app)
        status, body = self._request(
            "POST", f"/incidents/{incident_id}/preservation/orders",
            {"actor": LEGAL, "case_no": "CASE-HTTP", "purpose": "external_investigation",
             "receiver": dict(RECEIVER), "field_scope": ["victim_code", "content_ref"]})
        self.assertEqual(status, 201)
        order_id, manifest_id = body["order_id"], body["manifest_id"]

        # 非法务不能签发
        status, body = self._request(
            "POST", f"/incidents/{incident_id}/preservation/orders",
            {"actor": OFFICER, "purpose": "external_investigation",
             "receiver": RECEIVER, "field_scope": ["victim_code"]})
        self.assertEqual(status, 403)

        status, _ = self._request("POST", f"/manifests/{manifest_id}/ack",
                                  {"actor": OFFICER})
        self.assertEqual(status, 200)
        status, _ = self._request("POST", f"/manifests/{manifest_id}/ack",
                                  {"actor": EXTERNAL})
        self.assertEqual(status, 200)

        status, body = self._request("POST", f"/manifests/{manifest_id}/return",
                                     {"actor": EXTERNAL, "reason": "交出责任不清"})
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "returned")

        status, body = self._request(
            "POST", f"/preservation/orders/{order_id}/extend",
            {"actor": LEGAL, "reason": "司法延长", "duration_days": 30})
        self.assertEqual(status, 200)
        self.assertTrue(body["judicial"])

        # 追溯视图：普通查看者脱敏
        status, body = self._request(
            "GET", f"/incidents/{incident_id}/trace?as_role={quote('普通案件查看者')}")
        self.assertEqual(status, 200)
        self.assertTrue(body["masked"])
        self.assertEqual(body["preservation_orders"][0]["receiver"]["org_code"], "****")

        status, body = self._request("GET", f"/manifests/{manifest_id}")
        self.assertEqual(status, 200)
        self.assertEqual(body["manifest_id"], manifest_id)

        status, body = self._request("GET", f"/preservation/orders?incident_id={incident_id}")
        self.assertEqual(status, 200)
        self.assertTrue(any(o["order_id"] == order_id for o in body["orders"]))


if __name__ == "__main__":
    unittest.main()
