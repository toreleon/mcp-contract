# MCP-Contract Engine — Technical Spec (v0)

> **Một câu:** một engine runtime-agnostic đọc MCP tool manifest, tự suy ra
> sandbox policy tối thiểu, và giám sát hành vi thực tế của server để phát hiện
> khi nó làm vượt điều đã khai — coi manifest như một *hợp đồng* thực thi được.

Status: draft for build · Ngày: 2026 · Owner: (bạn)

---

## 0. Vì sao spec này tồn tại (đã verify)

Ba dữ kiện đã kiểm ở bước trước, là nền của mọi quyết định thiết kế dưới đây:

1. **Runtime hàng đầu chưa tự sinh policy.** Wassette (Microsoft, MCP-native,
   WASM) dùng mô hình *cấp quyền thủ công*: component khai năng lực qua WIT, và
   người/agent bấm cấp từng quyền một lúc runtime. Không có bước suy luận
   "manifest → policy tối thiểu".
2. **Schema policy đã có sẵn** (`policy-mcp`, Wassette v0.3.4). → Ta **không**
   phát minh schema mới; ta mở rộng cái đã có.
3. **Server thật hôm nay chạy đa-nền** (Docker / gVisor / Firecracker / WASM),
   và WASM-native (Wassette) còn vướng bài toán adoption (ít component). → Engine
   phải **runtime-agnostic**, không khoá vào một sandbox.

**Mối đe doạ cạnh tranh đã biết:** Anthropic self-hosted sandbox + MCP tunnels
(5/2026) đang platform-hoá phần "chạy tool trong perimeter khách". Spec này định
vị *tránh đối đầu trực diện*: nhắm **fleet MCP không đồng nhất** — thứ managed
offering đơn-nền không phục vụ.

**Cần verify trước khi code milestone 2** (chưa kiểm được, xem §12):
- Anthropic self-hosted sandbox có auto-sinh egress policy per-server không?
- `policy-mcp` schema biểu diễn được egress + fs + syscall tới mức nào?
- Đã có ai nối consistency-check vào *enforcement* runtime (không chỉ scan tĩnh)?

---

## 1. Scope & Non-goals

### In scope
- **PIE — Policy Inference Engine:** manifest (+ tùy chọn: static hints) →
  policy tối thiểu, ở định dạng `policy-mcp`-tương thích.
- **BCM — Behavioral Consistency Monitor:** quan sát hành vi runtime (network,
  fs, process, syscall) và đối chiếu với policy/manifest; báo cáo + (tùy chế độ)
  chặn khi lệch.
- **RAL — Runtime Adapter Layer:** một interface trừu tượng để PIE/BCM chạy
  trên nhiều sandbox backend mà không đổi lõi.

### Explicit non-goals (v0)
- **Không** tự viết sandbox mới — dùng gVisor/Firecracker/WASM/OCI runtime có sẵn.
- **Không** làm marketplace/registry MCP.
- **Không** làm static malware scanner tổng quát — đã đông (Invariant, Cisco,
  Snyk...). Ta chỉ làm phần *behavioral* (runtime) mà scanner tĩnh không thấy.
- **Không** làm eval/observability agent (đó là hướng khác, đã bỏ).
- **Không** hỗ trợ non-MCP workload trong v0.

---

## 2. Terminology

| Thuật ngữ | Nghĩa trong spec |
|---|---|
| **Manifest** | Danh sách tool một MCP server khai (tên, param schema, description). |
| **Capability** | Một quyền hệ thống cụ thể: egress host, fs path+mode, syscall group, env var, resource limit. |
| **Policy** | Tập capability được cấp cho một server, ở định dạng `policy-mcp`-compatible. |
| **Contract** | Manifest được coi như cam kết: "server chỉ làm bấy nhiêu". |
| **Drift / Violation** | Hành vi runtime vượt ngoài policy (hoặc ngoài điều manifest ngụ ý). |
| **Backend** | Một sandbox runtime cụ thể (Docker, gVisor, Firecracker, Wasmtime...). |

---

## 3. Kiến trúc tổng thể

```
                    ┌──────────────────────────────────────────┐
   MCP manifest ───▶│  PIE — Policy Inference Engine            │
   (+ static hints) │   parse → classify tools → infer caps     │──┐
                    │   → emit minimal policy (policy-mcp)       │  │
                    └──────────────────────────────────────────┘  │
                                                                   ▼
                    ┌──────────────────────────────────────────┐  policy.yaml
                    │  RAL — Runtime Adapter Layer               │◀─┘
                    │   translate policy → backend-native rules  │
                    │   (seccomp / egress proxy / WASM caps ...) │
                    └───────────────┬──────────────────────────┘
                                    │ apply @ boot
                                    ▼
             ┌──────────────────────────────────────────────────┐
             │  Sandbox backend (Docker / gVisor / µVM / WASM)   │
             │    ┌────────────────────────────────────────┐    │
             │    │  MCP server (untrusted)                 │    │
             │    └────────────────────────────────────────┘    │
             │            │ syscalls / net / fs                  │
             └────────────┼─────────────────────────────────────┘
                          ▼
             ┌──────────────────────────────────────────────────┐
             │  BCM — Behavioral Consistency Monitor             │
             │    collect events → diff vs policy+manifest       │
             │    → report / alert / (enforce mode: block)       │
             └──────────────────────────────────────────────────┘
```

Lõi (PIE + BCM + policy model) là **backend-agnostic**. Chỉ RAL biết chi tiết
từng sandbox. Thêm một backend = viết một adapter, không đụng lõi.

---

## 4. Component A — Policy Inference Engine (PIE)

### 4.1 Mục tiêu
Từ manifest, sinh ra policy **tối thiểu đủ chạy** (least-privilege), thay cho
việc người cấp quyền tay từng cái.

### 4.2 Input
- MCP manifest (bắt buộc): tool list + JSON Schema params + description.
- Static hints (tùy chọn, tăng độ chính xác): source/binary của server để phân
  tích tĩnh nhẹ (import mạng, path literal, `execve`...). Không bắt buộc — v0
  chạy được chỉ với manifest.
- User overrides (tùy chọn): pin/nới một capability cụ thể.

### 4.3 Pipeline
1. **Parse & normalize** manifest về IR nội bộ (`ToolIR`).
2. **Classify tool** theo capability-class — bằng luật + LLM-assist:
   - `net.http(host)` — cần egress; cố suy host từ param/description/URL literal.
   - `fs.read(path)` / `fs.write(path)` — cần mount; suy path/scope.
   - `proc.exec` — cần chạy shell/subprocess (cờ đỏ, mặc định deny).
   - `env(var)` — cần biến môi trường / secret.
   - `pure` — không cần I/O ngoài (vd tính toán).
3. **Aggregate → minimal caps:** hợp nhất capability của mọi tool thành policy
   hẹp nhất. Mặc định **deny-by-default**: cái gì không suy ra được thì *không*
   cấp (và đánh dấu `needs_review`).
4. **Emit** policy ở định dạng `policy-mcp`-compatible + phần mở rộng (§7).

### 4.4 Xử lý bất định (điểm thiết kế quan trọng)
Manifest thường **không đủ** để suy chính xác (vd `fetch(url)` — host là runtime
value). Ba mức output cho mỗi capability:
- **inferred** — suy chắc chắn (có host literal, path cố định).
- **needs_review** — biết *loại* quyền cần nhưng không biết phạm vi → cấp
  placeholder + đánh dấu để người xác nhận (đây là chỗ nối vào UX cấp-quyền, chứ
  không đoán bừa rồi cấp rộng).
- **denied** — không có tín hiệu nào cần → không cấp.

→ Khác biệt với Wassette: Wassette hỏi tay *tất cả*; PIE tự chốt phần `inferred`,
chỉ đẩy phần `needs_review` cho người → giảm số lần bấm tay, không hy sinh
least-privilege.

### 4.5 LLM-assist — có kiểm soát
Dùng LLM để đọc description/param và đề xuất classify, **nhưng**:
- LLM chỉ *đề xuất*, luật quyết định mức cuối; LLM không tự nới quyền.
- Mọi suy luận LLM ghi kèm evidence (câu/param nào dẫn tới) → auditable.
- Bài học từ VIPER-MCP đã verify: false-positive sinh ra khi LLM suy từ
  *description* thay vì *hành vi thực tế*. → PIE không dùng LLM để kết luận
  "an toàn/không"; chỉ dùng để *map sang loại capability*. Kết luận an toàn là
  việc của BCM (quan sát hành vi thật).

### 4.6 Output (ví dụ)
```yaml
# policy sinh cho một github-mcp giả định
schema: policy-mcp/v1        # tương thích schema đã có
x-mcp-contract:              # phần mở rộng của ta (§7)
  source_manifest_hash: sha256:...
  generated_by: mcp-contract/0.1
  caps:
    - id: net.http
      value: ["api.github.com"]
      status: inferred
      evidence: "tool list_issues description references GitHub REST API"
    - id: fs.read
      value: ["./repo"]
      status: needs_review     # scope suy được là ./repo nhưng chưa chắc
    - id: proc.exec
      status: denied           # không tool nào ngụ ý cần shell
```

---

## 5. Component B — Behavioral Consistency Monitor (BCM)

### 5.1 Mục tiêu
Đây là phần **defensible nhất** và là chỗ scanner tĩnh không với tới: xác minh
*hành vi runtime thực tế* của server có khớp với contract (manifest + policy)
không. Bắt đúng loại tấn công mà "đọc description" bỏ sót (server khai đọc file,
thực tế mở socket lạ).

### 5.2 Nguồn sự kiện (theo backend, qua RAL)
- **Network:** kết nối ra (host, port, khối lượng) — qua egress proxy / eBPF /
  WASM host-call log.
- **Filesystem:** open/read/write path + mode.
- **Process:** spawn/exec.
- **Syscall:** nhóm syscall bất thường (nếu backend cho — gVisor/seccomp).
- **MCP-layer:** tool nào được gọi, param gì (để gắn hành vi hệ thống với tool
  cụ thể — "read_file gây ra kết nối ra ngoài" là bất thường).

### 5.3 Diffing
Với mỗi sự kiện, phân loại:
- **within-policy** — đúng cái đã cấp. Bỏ qua (hoặc log mức debug).
- **within-manifest-not-policy** — manifest ngụ ý nhưng policy chưa cấp (khả năng
  PIE cấp thiếu) → gợi ý nới policy, không coi là tấn công.
- **outside-contract** — vượt cả manifest lẫn policy → **violation**. Đây là tín
  hiệu chính: server làm điều nó không khai.

### 5.4 Chế độ vận hành
- **observe** — chỉ ghi + báo cáo (an toàn để bật rộng, thu dữ liệu thật; cũng là
  cách trị false-positive: xem cái gì "outside-contract" thật sự nguy hiểm).
- **alert** — báo động realtime khi có violation.
- **enforce** — chặn hành động outside-contract ngay tại RAL (chỉ bật khi
  observe đã đủ tin).

### 5.5 Chống false-positive (bài học đã verify)
Nguồn gốc FP đã kiểm: các tool "nguy hiểm-do-thiết-kế" (server cố tình cho chạy
shell/thao tác file). BCM xử lý bằng cách **so với contract của chính server đó**,
không so với một chuẩn "an toàn" tuyệt đối: nếu manifest khai `proc.exec` và
người đã duyệt, thì exec **không** phải violation. Violation = *lệch khỏi điều đã
khai*, không phải *làm việc nguy hiểm*. Đây là điểm phân biệt cốt lõi với scanner
tĩnh.

---

## 6. Runtime Adapter Layer (RAL)

### 6.1 Vì sao
Runtime-agnostic là yêu cầu sống-còn (server thật chạy đa-nền). RAL là interface
mỏng; mỗi backend cài đặt nó.

### 6.2 Interface (phác thảo)
```python
class RuntimeAdapter(Protocol):
    name: str                      # "docker" | "gvisor" | "firecracker" | "wasmtime"

    # PIE side: dịch policy trung lập -> luật native của backend
    def apply_policy(self, policy: Policy, target: ServerHandle) -> None: ...

    # BCM side: đăng ký nguồn sự kiện; trả stream chuẩn hoá
    def event_stream(self, target: ServerHandle) -> Iterator[BehaviorEvent]: ...

    # enforce mode: chặn một hành động outside-contract
    def block(self, target: ServerHandle, action: BehaviorEvent) -> None: ...

    # năng lực backend hỗ trợ tới đâu (không phải backend nào cũng đủ)
    def capabilities(self) -> BackendCaps: ...
```

### 6.3 Ma trận năng lực backend (định hướng — cần verify khi cài)
| Backend | Egress control | FS scope | Syscall filter | Boot-time policy |
|---|---|---|---|---|
| Docker + seccomp | qua proxy | mount ro/rw | seccomp | có |
| gVisor | qua proxy | gofer | mạnh (chặn syscall) | có |
| Firecracker µVM | network device | virtio-fs | (trong guest) | có |
| Wasmtime / WASM | host-call cap | WASI preopens | (không syscall) | có (deny-default) |

→ v0 nên chọn **1 backend làm chuẩn tham chiếu** để ship nhanh; mình đề xuất
**Docker+seccomp+egress-proxy** (phổ biến nhất, khách infra dùng nhiều), rồi thêm
gVisor. WASM/Wassette để sau (adoption thấp).

---

## 7. Policy schema — mở rộng `policy-mcp` (contribution surface)

Không tạo schema mới. Dùng `policy-mcp/v1` làm base, thêm namespace
`x-mcp-contract` cho những gì base chưa có:
- `status` per-capability (`inferred` / `needs_review` / `denied`).
- `evidence` — dấu vết suy luận (auditable).
- `source_manifest_hash` — gắn policy với đúng version manifest (bắt "rug-pull":
  manifest đổi → hash đổi → policy phải sinh lại).
- `behavior_expectations` — điều BCM dùng làm mốc so hành vi.

**Đường contribute:** đề xuất đưa `status`/`evidence`/`hash` vào chính
`policy-mcp` upstream (mở rộng, không thay). Đây là cách cắm cờ "người trong cuộc"
với chi phí thấp — và làm engine của bạn nói cùng ngôn ngữ với runtime đã có.

---

## 8. Interfaces bên ngoài

### 8.1 CLI (developer-facing, kênh adoption)
```
mcp-contract infer   <manifest>            # sinh policy, in ra needs_review
mcp-contract run     <server> --backend docker --mode observe
mcp-contract audit   <server>              # báo cáo violation từ observe
mcp-contract verify  <server> <policy>     # CI: fail nếu có outside-contract
```

### 8.2 CI action (bắt đầu tạo audience nhanh)
Một GitHub Action gọi `verify` trong pipeline: chặn merge nếu MCP server mới có
hành vi outside-contract khi chạy test-suite trong observe mode.

### 8.3 API/SDK (infra-team, khách lõi)
Thư viện nhúng để fleet MCP tự sinh policy + monitor hàng loạt, xuất report
(SIEM/JSON). Đây là bề mặt biến thành sản phẩm trả tiền.

---

## 9. Threat model (v0)

| Đối tượng bảo vệ | Kẻ tấn công | Cơ chế |
|---|---|---|
| Dữ liệu host / API nội bộ | MCP server bị compromise/độc khai gian | PIE least-privilege + BCM chặn egress outside-contract |
| Rug-pull (server đổi hành vi sau khi được tin) | Server cập nhật lén | manifest hash + re-infer + BCM drift |
| Tool "benign-by-design" bị nhầm là độc | (false-positive) | BCM so với contract riêng, không so chuẩn tuyệt đối |
| Server khai gian manifest | Server khai ít làm nhiều | BCM = nguồn sự thật (hành vi thực), không chỉ tin manifest |

**Ngoài scope threat v0:** side-channel, tấn công vào chính sandbox backend,
supply-chain của binary (đó là việc của scanner tĩnh + signing — bổ trợ, không
thay).

---

## 10. Kiến trúc dữ liệu (tối giản)
- `ToolIR` — manifest chuẩn hoá.
- `Capability` — {id, value, status, evidence}.
- `Policy` — {server_id, manifest_hash, caps[], backend_hint}.
- `BehaviorEvent` — {ts, kind, detail, tool_ctx, classification}.
- `ViolationReport` — {server_id, events[], severity, suggested_action}.

---

## 11. Milestones (bám roadmap 6 tháng)

| Mốc | Nội dung | "Chạy được" nghĩa là |
|---|---|---|
| **M1** | PIE v0 + Docker adapter (observe) | `infer` sinh policy cho 10 server thật; chạy trong Docker, log hành vi |
| **M2** | BCM diffing + `verify` CI | Bắt được server test cố mở egress ngoài contract |
| **M3** | `policy-mcp` extension PR (upstream) + gVisor adapter | PR mở `status`/`evidence`; gVisor observe chạy |
| **M4** | enforce mode + rug-pull (hash re-infer) | Chặn được hành động outside-contract; phát hiện manifest đổi |
| **M5** | report/SIEM export + fleet API | Xuất report JSON cho nhiều server một lượt |
| **M6** | v1.0 + pilot với 1 infra-team | Một team chạy thật trên fleet của họ |

**Wedge tuần 1:** clone 15–20 MCP server phổ biến → viết `infer` tối giản
(manifest → danh sách capability-class, chưa cần sinh policy đầy đủ) → post
"đây là quyền tối thiểu 20 server này thực sự cần, so với quyền chúng thường được
cấp". Đó là demo cắm cờ, và là dữ liệu thật để hiệu chỉnh PIE.

---

## 12. Open questions — verify trước khi commit sâu

1. **Anthropic self-hosted sandbox** có auto-sinh egress policy per-server không?
   Nếu có → nhấn mạnh khách *fleet đa-nền* (nhóm nó không phục vụ).
2. **`policy-mcp` schema** hiện biểu diễn egress/fs/syscall tới đâu? Quyết định
   phần `x-mcp-contract` cần thêm gì.
3. **Đã có ai nối consistency-check vào enforcement runtime** chưa (không chỉ
   scan tĩnh)? Kiểm awesome-agent-runtime-security + các preprint
   description-code-inconsistency.
4. **eBPF vs proxy** cho thu network trên Docker/gVisor — tradeoff cài đặt.
5. Backend nào có đủ hook cho **enforce** (chặn realtime), backend nào chỉ
   **observe** được → xác định `BackendCaps` thật.

---

## 13. Caveat

Spec này dựng trên tài liệu/blog/preprint 2026 + repo Wassette công khai; các
nhận định "chưa ai tự sinh policy", "chưa nối consistency-check vào enforce" chưa
được verify bằng cách dựng thử. §12 là danh sách phải đóng trước khi đầu tư quá
M2. Mọi con số ecosystem trong các bước trước là chỉ báo từ nguồn thứ cấp, không
dùng để chốt pitch mà chưa kiểm primary.
