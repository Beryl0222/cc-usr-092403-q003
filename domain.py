"""领域配置加载与校验。

从 fixtures/domain.json 读取角色、严重度、授权范围、处置动作、值班规则、
聚类与申诉规则，供业务层统一引用，避免语义散落在代码里。
"""

import json
import os

FIXTURE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "domain.json")


class DomainError(ValueError):
    """领域配置不合法。"""


class DomainConfig:
    def __init__(self, data):
        self.data = data
        self.roles = set(data["参与角色"])
        self.statuses = set(data["参考状态"])
        self.severities = {item["编码"]: item for item in data["严重度"]}
        self.platforms = {item["编码"]: item for item in data["平台"]}
        self.scopes = {item["编码"]: item for item in data["授权范围"]}
        self.actions = {item["类型"]: item for item in data["处置动作"]}
        self.duty = data["值班规则"]
        self.appeal = data["误报申诉"]
        self.clustering = data["聚类"]
        self.consent_rules = data["授权规则"]
        self.separation = data["职责分离"]
        self.handoff = data["外部移交保全"]
        self._validate()

    def _validate(self):
        required_roles = {"当事人代理", "俱乐部保护专员", "俱乐部值班主管",
                          "平台联络员", "法务复核员", "外部调查机构", "普通案件查看者"}
        missing_roles = required_roles - self.roles
        if missing_roles:
            raise DomainError(f"领域配置缺少角色: {sorted(missing_roles)}")
        for code in ("criticism", "abuse", "direct_threat"):
            if code not in self.severities:
                raise DomainError(f"领域配置缺少严重度: {code}")
        for code in ("report", "evidence_storage", "platform_complaint",
                     "police_report", "public_statement", "external_disclosure"):
            if code not in self.scopes:
                raise DomainError(f"领域配置缺少授权范围: {code}")
        for action_type, item in self.actions.items():
            if item["复核角色"] not in self.roles:
                raise DomainError(f"动作 {action_type} 的复核角色未登记: {item['复核角色']}")
        for role in self.duty["通知角色"]:
            if role not in self.roles:
                raise DomainError(f"值班通知角色未登记: {role}")
        handoff = self.handoff
        if handoff["交出方角色"] not in self.roles or handoff["接收方角色"] not in self.roles:
            raise DomainError("移交交出/接收角色未登记")
        for group, fields in handoff["字段分组"].items():
            if not fields:
                raise DomainError(f"移交字段分组 {group} 为空")

    @property
    def default_scopes(self):
        return list(self.consent_rules["默认范围"])

    def severity(self, code):
        return self.severities.get(code)

    def is_valid_severity(self, code):
        return code in self.severities

    def is_openable_severity(self, code):
        item = self.severities.get(code)
        return bool(item and item["可立案"])

    def should_escalate(self, code):
        item = self.severities.get(code)
        return bool(item and item["自动升级"])

    def required_scopes_for(self, action_type):
        mapping = self.consent_rules["动作所需授权"]
        return list(mapping.get(action_type, []))

    def reviewer_role_for(self, action_type):
        item = self.actions.get(action_type)
        return item["复核角色"] if item else None

    @property
    def appeal_mask_fields(self):
        return list(self.appeal["敏感脱敏"])

    def appeal_can_view_sensitive(self, role):
        return role in self.appeal["可见角色例外"]

    # ------------------------------------------------------------ 外部移交保全
    @property
    def handoff_purposes(self):
        return list(self.handoff["移交用途"])

    @property
    def handoff_return_reasons(self):
        return list(self.handoff["退回原因"])

    @property
    def handoff_field_groups(self):
        return self.handoff["字段分组"]

    @property
    def default_field_scope(self):
        return list(self.handoff["默认字段范围"])

    def purpose_name(self, purpose):
        return self.handoff["用途名称"].get(purpose, purpose)

    def return_reason_name(self, reason):
        return self.handoff["退回原因名称"].get(reason, reason)

    def fields_for_groups(self, groups):
        """把字段分组展开为去重后的扁平字段列表，保持分组声明顺序。"""
        fields = []
        for group in groups:
            for field in self.handoff_field_groups.get(group, []):
                if field not in fields:
                    fields.append(field)
        return fields

    def handoff_can_view_unmasked(self, role):
        return role in self.handoff["普通查看脱敏"]["可见角色例外"]

    @property
    def handoff_mask_fields(self):
        return list(self.handoff["普通查看脱敏"]["脱敏字段"])

    @property
    def handoff_mask_placeholder(self):
        return self.handoff["普通查看脱敏"]["脱敏占位"]


def load_config(path=FIXTURE_PATH):
    with open(path, "r", encoding="utf-8") as handle:
        return DomainConfig(json.load(handle))
