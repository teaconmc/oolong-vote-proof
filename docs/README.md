# 基于 PS 签名的匿名投票与标识符方案

本方案面向需要同时平衡匿名性、抗滥用能力以及可撤销性的匿名投票场景。方案核心流程融合了类 OPAQUE 密码认证过程与 BLS12-381
双线性配对密码学。借助 VOPRF 机制，客户端可独立派生高熵私密种子，并在对其加密后安全交由服务端存储。在凭证签发阶段，方案借助
Pointcheval-Sanders 盲签名发放带有 Role-based 属性声明的匿名凭证，从而确保所有重复证明之间存在天然不可关联性。为抵御
Double-voting 与 Sybil 攻击，方案针对投票对象进一步派生各域内唯一但跨域脱钩的匿名标识符。最终，证明层将非交互式 Sigma
协议封装为二进制 NIZK 报文，并直接集成撤销机制，支持已认证用户通过可信信道安全撤销既有投票记录。

## 1. 密码学原语与系统参数

本方案运行在配对友好型椭圆曲线 BLS12-381 上，定义素数阶为 $p$。

* **群生成元及配对**：
    * $G$ 为 $\mathbb{G}$ 群的生成元。
    * $\tilde{G}$ 为 $\tilde{\mathbb{G}}$ 群的生成元。
    * $\tilde{G}_{neg} = (-1) \cdot \tilde{G}$ 为 $\tilde{\mathbb{G}}$ 的负生成元，用于通过配对等式校验抵消项。
    * $e: \mathbb{G} \times \tilde{\mathbb{G}} \to \mathbb{G}_T$ 为映射，满足双线性、非退化性与可计算性。
* **哈希函数**：
    * $H_p: \{0, 1\}^* \to \mathbb{G}$：将任意长度输入映射到 $\mathbb{G}$ 群上的点（Hash-to-Curve）。
    * $H_s: \{0, 1\}^* \to \mathbb{Z}_p$：将任意长度输入映射到标量域 $\mathbb{Z}_p$（Hash-to-Scalar）。
* **辅助函数**：
    * $\oplus$：一对等长字节序列的按位异或运算。
    * $\mathrm{HMAC}(\textit{key}, \textit{input})$：使用 $key$ 对 $input$ 计算 HMAC（基于 SHA512），输出 64 个字节。
    * $\mathrm{PBKDF2}(\mathrm{HMAC}, \textit{input}, \textit{iters}, \textit{count})$
      ：基于密码的密钥派生函数，取前 $\textit{count}$ 个字节。
* **系统参数**：
    * $seed$：服务端持有的私密派生令牌。
    * $uuid$：用户唯一标识符。
    * $role$：凭证中的角色属性。
    * $pass$：用户登录口令。
    * $mnem$：用户恢复助记词。
    * $salt$：信封与派生过程中的盐值。
    * $work$：投票对象或业务域标识。
    * $info$：投票时提交的公开信息。

## 2. 方案流程

### A. 服务端密钥对生成

1. **准备派生输入**：服务端持有不可对外公开的令牌 $seed$，对四个密钥对分别取盐值：
    * $(v, \tilde{V})$：将 `id-`、用户 $uuid$ 和 `-oprf-key` 拼接，例：`id-89abcdef-0123-4567-89ab-cdef01234567-oprf-key`。
    * $(w, \tilde{W}), (x, \tilde{X}), (y, \tilde{Y})$：分别使用常量 `role-key`，`base-key`，和 `bind-key`。
2. **密钥对派生**：
    * **私钥派生**：针对不同盐值计算 $H_s(\mathrm{PBKDF2}(\mathrm{HMAC}, \textit{seed}, 2048, 96))$
      得到服务端私钥，其中 $v$ 和用户有关，$SK = (w, x, y)$ 由 $seed$ 唯一决定。
    * **公钥计算**：进一步计算 $\tilde{V} = v \cdot \tilde{G}$
      和 $PK = (\tilde{W}, \tilde{X}, \tilde{Y}) = (w \cdot \tilde{G}, x \cdot \tilde{G}, y \cdot \tilde{G})$
      公钥，前者和用户有关，后者由 $seed$ 唯一决定。
    * **异常重试**：私钥派生有极低概率导致 $H_p$ 结果为 $0$。如 $\mathrm{PBKDF2}$ 输出无法满足要求，延长 96 字节输出，取最后
      96 字节计算直到私钥满足条件。
3. **伪输出派生**：
    * **准备伪派生输出**：将 `id-`、用户 $uuid$ 和 `-fake-key`
      拼接后计算 $\mathrm{PBKDF2}(\mathrm{HMAC}, \textit{seed}, 2048, 256)$。
    * **伪密钥派生**：取 $\mathrm{PBKDF2}$ 输出前 96 字节记为
      $\upsilon^{\ast}$ 并计算 $v^{\ast} = H_s(\upsilon^{\ast})$。后 160 字节按 32
      字节分割，记为 $(salt^{\ast}, \phi_{pass}^{\ast}, \psi_{pass}^{\ast}, \phi_{mnem}^{\ast}, \psi_{mnem}^{\ast})$。
    * **异常重试**：伪私钥派生有极低概率导致 $H_p$ 结果为 $0$。如 $\mathrm{PBKDF2}$ 输出无法满足要求，延长 96 字节输出，取最后
      256 字节计算直到私钥满足条件。

### B. 账户初始化与基于 VOPRF 的秘密种子派生

1. **盲化请求**：
    * 客户端输入登录密码 $pass$ 并计算哈希点 $P_{pass} = H_p(pass)$。
    * 选取随机盲化因子 $r \in \mathbb{Z}_p$，发送 `ClientPRFRequest` $M = r \cdot P_{pass}$ 至服务端。
2. **服务端响应**：
    * 服务端利用关联密钥 $v$ 计算 $N = v \cdot M$。
    * 服务端发送 `ServerPRFAbsent` $N$至客户端。
3. **密钥派生与秘密生成**：
    * 客户端计算 $v \cdot P_{pass} = r^{-1} \cdot N$。
    * 客户端在本地随机生成私钥 $s \in \mathbb{Z}_p$、恢复助记词 $mnem$ 和 32 字节随机序列 $salt$。
    * 执行 $\mathrm{PBKDF2}(\mathrm{HMAC}, H_s(pass, v \cdot P_{pass}), 2048, 64)$，取前 32 字节为 $\phi_{pass}$，后 32
      字节为 $\psi_{pass}$（盐值使用 `password`）。
    * 执行 $\mathrm{PBKDF2}(\mathrm{HMAC}, mnem, 2048, 64)$，取前 32 字节为 $\phi_{mnem}$，后 32 字节为 $\psi_{mnem}$（盐值使用
      `mnemonic`）。
4. **信封构造**：
    * 构造认证上下文 $\tau_{pass} = (salt, \psi_{pass} \oplus s, \tilde{V}, PK)$
      与 $\tau_{mnem} = (salt, \psi_{mnem} \oplus s, \tilde{V}, PK)$。
    * 计算认证码 $\alpha_{pass} = \mathrm{HMAC}(\phi_{pass}, \tau_{pass})$
      与 $\alpha_{mnem} = \mathrm{HMAC}(\phi_{mnem}, \tau_{mnem})$。
5. **提交覆盖凭证**：
    * 客户端计算 $S = (s \cdot G)$
      和 $\epsilon = (salt, \psi_{pass} \oplus s, \alpha_{pass}, \psi_{mnem} \oplus s, \alpha_{mnem})$。
    * 客户端提交 `ClientPRFOverride` $(S, \epsilon)$ 并由服务端存证。
6. **账户登录流程**：
    * 客户端发送 $M = r \cdot H_p(pass)$，服务端检查用户 $uuid$ 是否存在。
    * 服务端使用 $(salt^{\ast}, \phi_{pass}^{\ast}, \psi_{pass}^{\ast}, \phi_{mnem}^{\ast}, \psi_{mnem}^{\ast})$
      替代 $(salt, \phi_{pass}, \psi_{pass}, \phi_{mnem}, \psi_{mnem})$，$v^{\ast}$ 替代
      $v$，计算伪响应值 $(N^{\ast}, \epsilon^{\ast})$。
    * 如果 $uuid$ 存在则返回 `ServerPRFPresent` $(N, \epsilon)$，否则使用 $(N^{\ast}, \epsilon^{\ast})$ 防止客户端穷举用户注册情况。
    * 客户端恢复 $v \cdot P_{pass}$ 并通过 $pass$ 重新派生 $(\phi_{pass}, \psi_{pass})$。
    * 从 $\epsilon$ 中提取 $\psi_{pass} \oplus s$
      并校验 $\mathrm{HMAC}(\phi_{pass}, (salt, \psi_{pass} \oplus s, \tilde{V}, PK)) \stackrel{?}{=} \alpha_{pass}$。
    * 校验成功后恢复私钥 $s$。
7. **助记词恢复流程**：
    * 用户输入助记词 $mnem$，客户端从服务端请求获取信封 $\epsilon$。
    * 客户端通过 $mnem$ 重新派生 $(\phi_{mnem}, \psi_{mnem})$。
    * 从 $\epsilon$ 中提取 $\psi_{mnem} \oplus s$
      并校验 $\mathrm{HMAC}(\phi_{mnem}, (salt, \psi_{mnem} \oplus s, \tilde{V}, PK)) \stackrel{?}{=} \alpha_{mnem}$。
    * 校验成功后恢复私钥 $s$。

### C. Pointcheval-Sanders 盲签名授权

1. **权限申请**：
    * 客户端读取本地私钥 $s$ 并计算点承诺 $S = s \cdot G$。
    * 客户端发送 `ClientPointCommit` $S$ 至服务端。
2. **服务端盲签名**：
    * 服务端确认用户身份 $S$ 并指定 $role$。
    * 计算角色标量 $h_{role} = H_s(role)$。
    * 服务端选取随机数 $r \in \mathbb{Z}_p$。
    * 计算签名基点 $A = r \cdot G$。
    * 计算盲化签名 $B = (h_{role} \cdot w + x) \cdot A + y \cdot (r \cdot S)$。
    * 返回 `IdentitySignature` $\sigma = (role, A, B)$。
3. **凭证合法性核验**：
    * 客户端计算角色哈希 $h_{role} = H_s(role)$。
    * 校验配对等式
      $e(B, \tilde{G}_{neg}) \cdot e(A, h_{role} \cdot \tilde{W} + \tilde{X} + s \cdot \tilde{Y}) \stackrel{?}{=} 1_T$
      是否成立。
    * 若校验通过，则该凭证有效并存储。

### D. 匿名投票证明生成

1. **标识符派生**：
    * 计算投票对象 $work$ 的哈希点 $P_{work} = H_p(work)$。
    * 计算派生标识符 `IdentityDerivation` $ID = s \cdot P_{work}$。
2. **构造匿名证明**：
    * 选取随机数 $q, r \in \mathbb{Z}_p$。
    * 重随机化签名：$A' = q \cdot A, B' = q \cdot B$。
    * 生成承诺：$Q = r \cdot P_{work}$，$R = e(A', r \cdot \tilde{Y})$。
    * 生成挑战：$c = H_s(PK, H_s(work, ID, info, role, A', B'), Q, R)$。
    * 生成响应：$z = r + c \cdot s \pmod p$。
    * 构造证明：$\pi = (work, ID, info, role, A', B', c, z)$。
    * 提交 `IdentityBlindProof` $\pi$，包含公开信息 $info$（打分、评语）以及身份合法性证明。

### E. 投票有效性验证

1. **重构验证中间值**：$d' = H_s(work, ID, info, role, A', B')$ 和 $h_{role} = H_s(role)$。
2. **重建承诺**： $Q' = z \cdot P_{work} - c \cdot ID$
   和 $R' = e(A', c \cdot h_{role} \cdot \tilde{W} + c \cdot \tilde{X} + z \cdot \tilde{Y}) \cdot e(c \cdot B', \tilde{G}_{neg})$。
3. **结果裁定**：检查 $H_s(PK, d', Q', R') \stackrel{?}{=} c$。

### F. 用户手动撤销

1. **提交撤销原语**：用户通过认证信道发送 `ClientRevocation` $\tilde{C} = s \cdot \tilde{G}$。
2. **归属验证**：服务端核验 $e(S, \tilde{G}_{neg}) \cdot e(G, \tilde{C}) = 1_T$。
3. **追踪与清理**：检索数据库中满足 $e(ID, \tilde{G}) \stackrel{?}{=} e(P_{work}, \tilde{C})$ 的所有 $ID$
   并撤销对应的 $info$。

## 3. 详细等式证明

* **VOPRF 验证证明**  
  $e(N, \tilde{G}_{neg}) \cdot e(M, \tilde{V}) = e(v \cdot M, \tilde{G})^{-1} \cdot e(M, v \cdot \tilde{G}) = e(M, \tilde{G})^{-v} \cdot e(M, \tilde{G})^v = 1_T$
* **盲签名验证证明**  
  $e(B, \tilde{G}_{neg}) \cdot e(A, h_{role} \cdot \tilde{W} + \tilde{X} + s \cdot \tilde{Y}) = e((h_{role} \cdot w + x + s \cdot y) \cdot A, \tilde{G}_{neg}) \cdot e(A, (h_{role} \cdot w + x + s \cdot y) \cdot \tilde{G}) = 1_T$
* **匿名证明 $Q'$ 重建证明**  
  $Q' = z \cdot P_{work} - c \cdot ID = (r + c \cdot s) \cdot P_{work} - c \cdot (s \cdot P_{work}) = r \cdot P_{work} + (c \cdot s - c \cdot s) \cdot P_{work} = Q$
* **匿名证明 $R'$ 重建证明**  
  $\begin{aligned} R' &= e(A', c \cdot h_{role} \cdot \tilde{W} + c \cdot \tilde{X} + z \cdot \tilde{Y}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= e(A', c \cdot h_{role} \cdot \tilde{W} + c \cdot \tilde{X} + (r + c \cdot s) \cdot \tilde{Y}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= e(A', r \cdot \tilde{Y}) \cdot e(A', c \cdot (h_{role} \cdot \tilde{W} + s \cdot \tilde{Y} + \tilde{X})) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= R \cdot e(c \cdot A', (h_{role} \cdot w + x + s \cdot y) \cdot \tilde{G}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= R \cdot e(c \cdot (h_{role} \cdot w + x + s \cdot y) \cdot A', \tilde{G}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= R \cdot e(c \cdot B', \tilde{G}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= R \end{aligned}$
* **撤销归属验证证明**  
  $e(S, \tilde{G}_{neg}) \cdot e(G, \tilde{C}) = e(s \cdot G, \tilde{G}_{neg}) \cdot e(G, s \cdot \tilde{G}) = e(G, \tilde{G})^{-s} \cdot e(G, \tilde{G})^s = 1_T$
* **撤销标识符检索证明**  
  $e(ID, \tilde{G}) = e(s \cdot P_{work}, \tilde{G}) = e(P_{work}, s \cdot \tilde{G}) = e(P_{work}, \tilde{C})$

## 4. 实体对象映射表

| 类名                   | 对应方案变量                                       | 字节数 (BLS12-381)                                 |
|:---------------------|:---------------------------------------------|:------------------------------------------------|
| `ClientPointCommit`  | $S = s \cdot G$                              | $48$                                            |
| `ClientPRFOverride`  | $(S, \epsilon)$                              | $272$                                           |
| `ClientPRFRequest`   | $M = r \cdot P_{pass}$                       | $48$                                            |
| `ClientRevocation`   | $\tilde{C} = s \cdot \tilde{G}$              | $96$                                            |
| `ClientSecretKey`    | $s$                                          | $32$                                            |
| `IdentityDerivation` | $ID = s \cdot P_{work}$                      | $48$                                            |
| `IdentityBlindProof` | $\pi = (work, ID, info, role, A', B', c, z)$ | $224 + \mathrm{len}(role) + \mathrm{len}(info)$ |
| `IdentitySignature`  | $\sigma = (role, A, B)$                      | $96 + \mathrm{len}(role)$                       |
| `ServerPRFAbsent`    | $N = v \cdot M$                              | $48$                                            |
| `ServerPRFPresent`   | $(N, \epsilon)$                              | $272$                                           |
| `ServerPublicKey`    | $(\tilde{V}, PK)$                            | $384$                                           |
| `ServerSecretKey`    | $(v, SK)$                                    | $128$                                           |

***

# Anonymous Voting and ID Scheme via PS Signatures

This scheme is designed for anonymous voting scenarios that balance privacy, abuse resistance, and revocability at once.
Its core flow combines an OPAQUE-like password authentication process with the BLS12-381 bilinear pairing cryptography.
With the help of a VOPRF, the client can independently derive a high-entropy private seed and then, after encrypting it,
securely sent to the server for storage. During credential issuance, the scheme uses blind signatures which are based on
the Pointcheval-Sanders construction to issue anonymous credentials carrying role-based attribute claims, ensuring that
naturally repeated proof presentations remain unlinkable. For voting targets, in order to resist Double-voting and Sybil
attacks, the scheme further derives anonymous identifiers that are unique within each domain yet decoupled across other
domains. Finally, the proof layer packages non-interactive Sigma protocols into binary NIZK payloads and also directly
integrates a revocation mechanism for authenticated end users, allowing them to securely revoke existing voting records
through trusted channels.

## 1. Cryptographic Primitives and System Parameters

The scheme is implemented on the pairing-friendly elliptic curve BLS12-381 with a prime order $p$.

* **Group Generators and Pairing**:
    * $G$ is the generator of group $\mathbb{G}$.
    * $\tilde{G}$ is the generator of group $\tilde{\mathbb{G}}$.
    * $\tilde{G}_{neg} = (-1) \cdot \tilde{G}$ is the negative generator of $\tilde{\mathbb{G}}$, used for cancellation
      in pairing verification equations.
    * $e: \mathbb{G} \times \tilde{\mathbb{G}} \to \mathbb{G}_T$ is a map that satisfies bilinearity, non-degeneracy,
      and computability.
* **Hash Functions**:
    * $H_p: \{0, 1\}^* \to \mathbb{G}$: Maps an arbitrary string to a point in $\mathbb{G}$ (Hash-to-Curve).
    * $H_s: \{0, 1\}^* \to \mathbb{Z}_p$: Maps an arbitrary string to a scalar in $\mathbb{Z}_p$ (Hash-to-Scalar).
* **Auxiliary Functions**:
    * $\oplus$: Bitwise XOR over equal-length byte strings.
    * $\mathrm{HMAC}(\textit{key}, \textit{input})$: HMAC computation (based on SHA512) over $\textit{input}$ keyed
      by $\textit{key}$, with a 64-byte output.
    * $\mathrm{PBKDF2}(\mathrm{HMAC}, \textit{input}, \textit{iters}, \textit{count})$: A password-based key derivation
      function; outputs the first $\textit{count}$ bytes.
* **System Parameters**:
    * $seed$: Server-held secret derivation token.
    * $uuid$: Unique user identifier.
    * $role$: Role attribute in credentials.
    * $fake$: Fixed label used for fake-output derivation (mapped to `fake-key`).
    * $pass$: User login password.
    * $mnem$: User recovery mnemonic.
    * $salt$: Salt used in envelope and derivation steps.
    * $work$: Voting target or domain identifier.
    * $info$: Public payload submitted with a vote.

## 2. Scheme Process Flow

### A. Server Key Pair Generation

1. **Prepare Derivation Inputs**: Server holds a non-public token $seed$ and uses different salts for four key pairs:
    * $(v, \tilde{V})$: concatenate `id-`, user $uuid$, and `-oprf-key`, e.g.
      `id-89abcdef-0123-4567-89ab-cdef01234567-oprf-key`.
    * $(w, \tilde{W}), (x, \tilde{X}), (y, \tilde{Y})$: use constants `role-key`, `base-key`, and `bind-key`,
      respectively.
2. **Key Pair Derivation**:
    * **Private-Key Derivation**: For each salt, compute $H_s(\mathrm{PBKDF2}(\mathrm{HMAC}, \textit{seed}, 2048, 96))$
      to get server private keys, where $v$ is user-associated while $SK = (w, x, y)$ is uniquely determined by $seed$.
    * **Public-Key Computation**: Further compute $\tilde{V} = v \cdot \tilde{G}$ and
      $PK = (\tilde{W}, \tilde{X}, \tilde{Y}) = (w \cdot \tilde{G}, x \cdot \tilde{G}, y \cdot \tilde{G})$ public keys,
      where the former is user-associated and the latter is uniquely determined by $seed$.
    * **Retry Rule**: With extremely low probability, private-key derivation may lead to $H_p$ output being $0$. If
      the $\mathrm{PBKDF2}$ output does not satisfy the requirement, extend it by another 96 bytes and use the last
      96 bytes for computation until the private key satisfies the condition.
3. **Fake Output Derivation**:
    * **Prepare Fake Derived Output**: Concatenate `id-`, user $uuid$, and `-fake-key` as the salt, then compute
      $\mathrm{PBKDF2}(\mathrm{HMAC}, \textit{seed}, 2048, 256)$.
    * **Fake Key and Envelope Derivation**: Take the first 96 bytes of the $\mathrm{PBKDF2}$ output as $\upsilon^{\ast}$
      and compute
      $v^{\ast} = H_s(\upsilon^{\ast})$. Split the last $160$ bytes into five 32-byte chunks:
      $(salt^{\ast}, \phi_{pass}^{\ast}, \psi_{pass}^{\ast}, \phi_{mnem}^{\ast}, \psi_{mnem}^{\ast})$.
    * **Retry Rule**: With extremely low probability, fake private-key derivation may lead to $H_p$ output being
      $0$. If the $\mathrm{PBKDF2}$ output does not satisfy the requirement, extend it by another $96$ bytes and use
      the last $256$ bytes for computation until the private key satisfies the condition.

### B. Account Initialization and Secret Seed Derivation Based on VOPRF

1. **Blinding Request**:
    * Client inputs the password $pass$ and computes hash point $P_{pass} = H_p(pass)$.
    * Selects random blinding factor $r \in \mathbb{Z}_p$ and sends `ClientPRFRequest` $M = r \cdot P_{pass}$ to the
      server.
2. **Server Response**:
    * Server uses associated key $v$ to compute $N = v \cdot M$.
    * Server sends `ServerPRFAbsent` $N$ to
      the client.
3. **Key Derivation and Secret Generation**:
    * Client computes $v \cdot P_{pass} = r^{-1} \cdot N$.
    * Client locally generates secret key $s \in \mathbb{Z}_p$, recovery mnemonic $mnem$, and a 32-byte random $salt$.
    * Execute $\mathrm{PBKDF2}(\mathrm{HMAC}, H_s(pass, v \cdot P_{pass}), 2048, 64)$: the first 32 bytes
      are $\phi_{pass}$, the latter 32 bytes are $\psi_{pass}$ (salt uses `password`).
    * Execute $\mathrm{PBKDF2}(\mathrm{HMAC}, mnem, 2048, 64)$: the first 32 bytes are $\phi_{mnem}$, the latter 32
      bytes are $\psi_{mnem}$ (salt uses `mnemonic`).
4. **Envelope Construction**:
    * Construct authentication contexts $\tau_{pass} = (salt, \psi_{pass} \oplus s, \tilde{V}, PK)$
      and $\tau_{mnem} = (salt, \psi_{mnem} \oplus s, \tilde{V}, PK)$.
    * Compute authentication codes $\alpha_{pass} = \mathrm{HMAC}(\phi_{pass}, \tau_{pass})$
      and $\alpha_{mnem} = \mathrm{HMAC}(\phi_{mnem}, \tau_{mnem})$.
5. **Override Credential Submission**:
    * Client computes $S = s \cdot G$
      and $\epsilon = (salt, \psi_{pass} \oplus s, \alpha_{pass}, \psi_{mnem} \oplus s, \alpha_{mnem})$.
    * Client submits `ClientPRFOverride` $(S, \epsilon)$, which is stored by the server.
6. **Account Login Flow**:
    * Client sends $M = r \cdot H_p(pass)$, and server checks whether user $uuid$ exists.
    * Server computes fake envelope $\epsilon^{\ast}$ by letting $s = 0$ and replacing
      $(salt, \phi_{pass}, \psi_{pass}, \phi_{mnem}, \psi_{mnem})$ with
      $(salt^{\ast}, \phi_{pass}^{\ast}, \psi_{pass}^{\ast}, \phi_{mnem}^{\ast}, \psi_{mnem}^{\ast})$.
    * Server computes fake response $N^{\ast} = v^{\ast} \cdot M$.
    * Server return `ServerPRFPresent` $(N, \epsilon)$ if $uuid$ exists; otherwise return $(N^{\ast}, \epsilon^{\ast})$
      to prevent client-side user enumeration.
    * Client recovers $v \cdot P_{pass}$ and re-derives $(\phi_{pass}, \psi_{pass})$ via $pass$.
    * Extract $\psi_{pass} \oplus s$ from $\epsilon$ and
      verify $\mathrm{HMAC}(\phi_{pass}, (salt, \psi_{pass} \oplus s, \tilde{V}, PK)) \stackrel{?}{=} \alpha_{pass}$.
    * Upon success, recover secret key $s$.
7. **Mnemonic Recovery Flow**:
    * User inputs $mnem$, client requests envelope $\epsilon$ from the server.
    * Client re-derives $(\phi_{mnem}, \psi_{mnem})$ via $mnem$.
    * Extract $\psi_{mnem} \oplus s$ from $\epsilon$ and
      verify $\mathrm{HMAC}(\phi_{mnem}, (salt, \psi_{mnem} \oplus s, \tilde{V}, PK)) \stackrel{?}{=} \alpha_{mnem}$.
    * Upon success, recover secret key $s$.

### C. Pointcheval-Sanders Blind Signature Issuance

1. **Request Phase**:
    * Client retrieves the local secret key $s$ and computes $S = s \cdot G$.
    * Sends `ClientPointCommit` $S$ to the server.
2. **Server Blind Signing**:
    * Server verifies user identity $S$ and assigns a $role$.
    * Computes the role scalar $h_{role} = H_s(role)$.
    * Server selects a random scalar $r \in \mathbb{Z}_p$.
    * Computes signature base $A = r \cdot G$.
    * Computes blinded signature $B = (h_{role} \cdot w + x) \cdot A + y \cdot (r \cdot S)$.
    * Returns `IdentitySignature` $\sigma = (role, A, B)$.
3. **Credential Validation**:
    * Client computes the role hash $h_{role} = H_s(role)$.
    * Checks if the pairing equation
      $e(B, \tilde{G}_{neg}) \cdot e(A, h_{role} \cdot \tilde{W} + \tilde{X} + s \cdot \tilde{Y}) \stackrel{?}{=} 1_T$
      holds.
    * If verified, the credential is valid and stored.

### D. Anonymous Voting Proof Generation

1. **Identifier Derivation**:
    * Map the voting target $work$ to hash point $P_{work} = H_p(work)$.
    * Compute `IdentityDerivation` $ID = s \cdot P_{work}$.
2. **Construct Anonymous Proof**:
    * Select random numbers $q, r \in \mathbb{Z}_p$.
    * Re-randomize signature: $A' = q \cdot A, B' = q \cdot B$.
    * Compute commitments: $Q = r \cdot P_{work}$, $R = e(A', r \cdot \tilde{Y})$.
    * Compute challenge: $c = H_s(PK, H_s(work, ID, info, role, A', B'), Q, R)$.
    * Compute response: $z = r + c \cdot s \pmod p$.
    * Construct proof: $\pi = (work, ID, info, role, A', B', c, z)$.
    * Submit `IdentityBlindProof` $\pi$ including public data $info$ (scores, comments) and a ZKP for identity validity.

### E. Verification of Vote Validity

1. **Reconstruct Intermediate Values**: $d' = H_s(work, ID, info, role, A', B')$ and $h_{role} = H_s(role)$.
2. **Reconstruct Commitments**: $Q' = z \cdot P_{work} - c \cdot ID$
   and $R' = e(A', c \cdot h_{role} \cdot \tilde{W} + c \cdot \tilde{X} + z \cdot \tilde{Y}) \cdot e(c \cdot B', \tilde{G}_{neg})$.
3. **Decision**: Check if $H_s(PK, d', Q', R') \stackrel{?}{=} c$.

### F. Manual User Revocation

1. **Submit Revocation Token**: User sends `ClientRevocation` $\tilde{C} = s \cdot \tilde{G}$ through a trusted channel.
2. **Attribution Verification**: Server verifies $e(S, \tilde{G}_{neg}) \cdot e(G, \tilde{C}) = 1_T$.
3. **Trace and Cleanup**: Search for all $ID$ satisfying $e(ID, \tilde{G}) \stackrel{?}{=} e(P_{work}, \tilde{C})$ and
   revoke the corresponding $info$.

## 3. Detailed Equality Proofs

* **VOPRF Verification Proof**  
  $e(N, \tilde{G}_{neg}) \cdot e(M, \tilde{V}) = e(v \cdot M, \tilde{G})^{-1} \cdot e(M, v \cdot \tilde{G}) = e(M, \tilde{G})^{-v} \cdot e(M, \tilde{G})^v = 1_T$
* **Blind Signature Verification Proof**  
  $e(B, \tilde{G}_{neg}) \cdot e(A, h_{role} \cdot \tilde{W} + \tilde{X} + s \cdot \tilde{Y}) = e((h_{role} \cdot w + x + s \cdot y) \cdot A, \tilde{G}_{neg}) \cdot e(A, (h_{role} \cdot w + x + s \cdot y) \cdot \tilde{G}) = 1_T$
* **Anonymous Proof $Q'$ Reconstruction**  
  $Q' = z \cdot P_{work} - c \cdot ID = (r + c \cdot s) \cdot P_{work} - c \cdot (s \cdot P_{work}) = r \cdot P_{work} + (c \cdot s - c \cdot s) \cdot P_{work} = Q$
* **Anonymous Proof $R'$ Reconstruction**  
  $\begin{aligned} R' &= e(A', c \cdot h_{role} \cdot \tilde{W} + c \cdot \tilde{X} + z \cdot \tilde{Y}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= e(A', c \cdot h_{role} \cdot \tilde{W} + c \cdot \tilde{X} + (r + c \cdot s) \cdot \tilde{Y}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= e(A', r \cdot \tilde{Y}) \cdot e(A', c \cdot (h_{role} \cdot \tilde{W} + s \cdot \tilde{Y} + \tilde{X})) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= R \cdot e(c \cdot A', (h_{role} \cdot w + x + s \cdot y) \cdot \tilde{G}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= R \cdot e(c \cdot (h_{role} \cdot w + x + s \cdot y) \cdot A', \tilde{G}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= R \cdot e(c \cdot B', \tilde{G}) \cdot e(c \cdot B', \tilde{G}_{neg}) \\ &= R \end{aligned}$
* **Revocation Attribution Proof**  
  $e(S, \tilde{G}_{neg}) \cdot e(G, \tilde{C}) = e(s \cdot G, \tilde{G}_{neg}) \cdot e(G, s \cdot \tilde{G}) = e(G, \tilde{G})^{-s} \cdot e(G, \tilde{G})^s = 1_T$
* **Revocation Identifier Retrieval Proof**  
  $e(ID, \tilde{G}) = e(s \cdot P_{work}, \tilde{G}) = e(P_{work}, s \cdot \tilde{G}) = e(P_{work}, \tilde{C})$

## 4. Entity Mapping Table

| Class Name           | Corresponding Variable                       | Bytes (BLS12-381)                               |
|:---------------------|:---------------------------------------------|:------------------------------------------------|
| `ClientPointCommit`  | $S = s \cdot G$                              | $48$                                            |
| `ClientPRFOverride`  | $(S, \epsilon)$                              | $272$                                           |
| `ClientPRFRequest`   | $M = r \cdot P_{pass}$                       | $48$                                            |
| `ClientRevocation`   | $\tilde{C} = s \cdot \tilde{G}$              | $96$                                            |
| `ClientSecretKey`    | $s$                                          | $32$                                            |
| `IdentityDerivation` | $ID = s \cdot P_{work}$                      | $48$                                            |
| `IdentityBlindProof` | $\pi = (work, ID, info, role, A', B', c, z)$ | $224 + \mathrm{len}(role) + \mathrm{len}(info)$ |
| `IdentitySignature`  | $\sigma = (role, A, B)$                      | $96 + \mathrm{len}(role)$                       |
| `ServerPRFAbsent`    | $N = v \cdot M$                              | $48$                                            |
| `ServerPRFPresent`   | $(N, \epsilon)$                              | $272$                                           |
| `ServerPublicKey`    | $(\tilde{V}, PK)$                            | $384$                                           |
| `ServerSecretKey`    | $(v, SK)$                                    | $128$                                           |
