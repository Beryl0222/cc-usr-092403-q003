# 运动员网络权益保护

围绕赛事参与者遭遇网络侵害后的**受理、保护、复核与协同处置**建立统一服务，替代截图+群聊报送：当事人或授权代理提交线索后，系统按严重度分流立案，组织受控证据、平台回执、威胁等级与关联账号，并把每个保护动作的责任落到具体角色。

## 核心规则

- **严重度分流**：普通批评（criticism）只登记线索观察、不立事件；一般网暴（abuse）立案常规处置；直接人身威胁（direct_threat）立案即按值班规则升级，通知值班主管与保护专员。
- **受控证据**：原始内容不入库，只保存内容引用（URL）与 SHA-256 哈希；证据补充同样只收引用。
- **责任链不可变**：内容删除、账号改名、证据补充、授权撤回均只追加事件（JSONL 账本），不覆盖旧记录，任意时刻可还原全过程。
- **自动聚类只建议**：同当事人+同内容哈希、或共享关联账号时生成合并建议，须保护专员人工确认才合并。
- **职责分离**：平台投诉→平台联络员复核；报案、公开澄清→法务复核员复核；提交人不得复核自己发起的动作。
- **授权驱动**：当事人当前授权不足时，已批准的对外动作保持 blocked；撤回授权不抹除已完成动作与既有责任链；申诉/司法程序存续期间证据留存授权不可撤回。
- **回调幂等**：平台回调按 `callback_id` 去重，重复回调返回 `duplicate=true`，不通知、不产生第二案件、不重复挂回执；回调无法凭匿名内容另立案件。
- **误报申诉**：申诉期间事件置"申诉中"，敏感材料仅法务复核员与值班主管可见，并阻断新的对外动作。
- **直接威胁去重**：同一事件值班周期内重复确认威胁等级只刷新确认时间，不产生第二案件或第二次通知。
- **法务保全令**：法务按案件+用途签发带**版本、期限、字段范围**的保全令；系统据此刻录**不可变材料清单与摘要**（含 SHA-256、保管人、到期日），换版须显式 `supersedes`，旧版与旧清单均留存。
- **双方签认**：移交由交出方（保护专员）先签认、接收方（外部调查机构）再签认；外部机构对来源、交出责任、授权期限无法确认时可**拒收/退回（可逐项部分退回）**，拒收、退回、补件、**司法延长**都只追加后续事件，不改写先前签认回执。
- **补件重新核权**：撤回 `external_disclosure` 等非核心授权后，已依法保全的最小材料继续留存，但任何**新增披露（含补件）须重新核权**；补件生成新清单并衔接回原移交，原通知不重发。
- **重复移交幂等与冲突复核**：同（保全令+接收机构+用途）重复移交不发通知、不生第二份清单；案件材料相对原清单发生变化（如账号改名）时进入冲突复核，由法务裁定维持原清单或要求补件。
- **断点恢复**：移交记录最后账本序号与最后确认节点，服务中断后经 JSONL 重放从该节点恢复，重复移交仍保持幂等。
- **案件追溯与脱敏**：逐项说明材料**为何保全、由谁保管、何时到期、缺哪些外部回执**；普通案件查看者只能获得其角色允许的脱敏内容（受控引用、账号键、URL、当事人码、接收方等不可见）。

## 运行

```bash
python3 service.py --check          # 检查配置与可重放账本
python3 service.py --port 8000      # 内存账本（联调）
python3 service.py --data data/events.jsonl   # 追加式持久化账本（重启可重放）
npm test                            # 全部契约测试（46 项）
```

## HTTP 接口

所有写操作在请求体携带 `actor: {"name","role"}`；角色取值见 `fixtures/domain.json`。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` `/domain` | 健康检查、领域配置（角色/严重度/动作/规则） |
| POST | `/reports` | 报送线索；按严重度决定不立案或开新事件并返回 `incident_id` |
| POST | `/severity/suggest` | 联调辅助：按文本给严重度建议（不替代人工判定） |
| GET | `/reports` `/incidents` `/suggestions` `/notifications` | 列表（支持 status/severity/as_role 过滤） |
| GET | `/incidents/{id}/digest?as_role=…` | **保护专员统一视图**：证据依据、处置决定、当事人当前授权范围、尚未完成的保护动作、值班升级、责任链 |
| POST | `/incidents/{id}/severity` | 保护专员确认/调整严重度 |
| POST | `/incidents/{id}/escalation/ack` | 值班主管响应升级 |
| POST | `/incidents/{id}/evidence` | 补充受控证据（只收 `content_ref` + 可选哈希） |
| POST | `/incidents/{id}/accounts` | 登记关联账号 |
| POST | `/incidents/{id}/actions` | 发起处置动作（返回所需复核角色） |
| POST | `/actions/{id}/review` `/actions/{id}/execute` | 分角色复核、复核通过后执行（执行时再次校验授权） |
| POST | `/incidents/{id}/consent/grant` `/consent/revoke` | 当事人代理授予/撤回授权 |
| POST | `/incidents/{id}/appeal` `/appeal/resolve` | 发起误报申诉、法务裁定（upheld/dismissed） |
| POST | `/incidents/{id}/preservation-orders` | **法务签发保全令**（purpose、valid_from/until、field_groups、换版 supersedes），返回不可变清单 id 与摘要哈希 |
| POST | `/preservation-orders/{id}/extend` | 司法延长保全期限（司法延长须附 legal_ref），只追加、不改令 |
| POST | `/incidents/{id}/handoffs` | 交出方按保全令向外部机构移交；重复移交返回 `duplicate=true`，内容变化进入冲突复核 |
| POST | `/handoffs/{id}/surrender-ack` `/receiver-ack` | 交出方、接收方分别签认 |
| POST | `/handoffs/{id}/reject` `/return` `/supplement` | 接收方拒收/退回（可带 items 部分退回）、交出方补件（新增披露重新核权） |
| POST | `/handoffs/{id}/resume` | 服务中断后的最后确认节点与账本序号 |
| POST | `/conflicts/{id}/resolve` | 法务/交出方冲突复核（accept_existing/require_supplement） |
| GET | `/incidents/{id}/traceability?as_role=…` | **案件追溯**：逐项为何保全/谁保管/何时到期/缺失回执；普通查看者脱敏 |
| GET | `/preservation-orders` `/handoffs` `/handoffs/{id}` | 保全令、移交列表与移交详情（支持 incident_id/state/as_role 过滤） |
| POST | `/suggestions/{id}` | 保护专员 accept/reject 合并建议（accept 时给 `target_incident`） |
| POST | `/callbacks/platform` | 平台/采集回调（幂等键 `callback_id`；可携带回执、删除状态、改名信息） |
| POST | `/incidents/{id}/close` | 关闭事件（存在未响应升级或未完成动作时拒绝） |

## 代码结构

- `fixtures/domain.json` — 角色、严重度、授权范围、处置动作、值班规则、聚类/申诉规则、平台与回执样例、外部移交保全规则
- `domain.py` — 领域配置加载与校验
- `store.py` — 线程安全的追加式事件账本（内存或 JSONL，重放恢复）
- `app.py` — 业务核心：受理立案、升级、证据/账号、聚类、动作复核、授权、申诉、幂等回调、统一视图、法务保全令/不可变清单/外部移交签认/冲突复核/案件追溯
- `service.py` — HTTP 入口
- `service_contract.py` / `test_safeguarding.py` / `test_preservation.py` — 基础契约、处置全链路、移交保全全链路测试

## 运行与检查

```bash
python3 service.py --check
npm test
python3 -m compileall -q .
```
