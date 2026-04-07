# 基于 PS 签名的匿名投票凭证与标识符派生方案

本方案为匿名投票场景设计，基于 BLS12-381 双线性配对曲线，利用 VOPRF 机制确保系统服务端和用户共同派生高熵秘密。采用可重随机化的
Pointcheval-Sanders 盲签名在签发阶段授予 Role-based 属性声明的匿名凭证，保障身份在多次调用证明接口时具备天然不可关联性。针对
16 字节 UUID 的投票对象，系统派生出域内唯一但跨域脱钩的匿名标识符，原生防止 Double-voting 以及 Sybil 攻击。证明层将非交互式
Sigma 协议封装为 NIZK 二进制报文，并内置撤销机制，允许系统引导用户通过安全信道撤销历史投票记录。

## 1. 密码学原语与系统参数

本方案运行在配对友好型椭圆曲线 BLS12-381 上，定义素数阶为 $p$。

* **双线性配对**：定义映射 $e: \mathbb{G} \times \tilde{\mathbb{G}} \to \mathbb{G}_T$，满足双线性、非退化性与可计算性。
* **群生成元**：
    * $G$ 为 $\mathbb{G}$ 群的生成元。
    * $\tilde{G}$ 为 $\tilde{\mathbb{G}}$ 群的生成元。
    * $\tilde{G}_{neg} = (-1) \cdot \tilde{G}$ 为 $\tilde{\mathbb{G}}$ 的负生成元，用于通过配对等式校验抵消项。
* **哈希函数**：
    * $H_p: \{0, 1\}^* \to \mathbb{G}$：将任意长度输入映射到 $\mathbb{G}$ 群上的点（Hash-to-Curve）。
    * $H_s: \{0, 1\}^* \to \mathbb{Z}_p$：将任意长度输入映射到标量域 $\mathbb{Z}_p$（Hash-to-Scalar）。
* **辅助函数**：
    * $\oplus$：等长字节序列的按位异或运算。
    * $\mathrm{PBKDF2}(\textit{input}, \textit{iters})$：基于密码的密钥派生函数，输出序列一分为二，记为 $(H, L)$ 两部分。
* **服务端密钥对**：
    * **私钥 ($SK$)**：随机标量元组 $(v, w, x, y) \in \mathbb{Z}_p^4$。
    * **公钥 ($PK$)**：由 $\tilde{\mathbb{G}}$
      群中的点构成的元组：$PK = (\tilde{V}, \tilde{W}, \tilde{X}, \tilde{Y}) = (v \cdot \tilde{G}, w \cdot \tilde{G}, x \cdot \tilde{G}, y \cdot \tilde{G})$。

## 2. 方案流程

### A. 账户初始化与基于 VOPRF 的秘密种子派生

1. **初始请求与信封提交**：
    * 客户端生成随机 `ClientSecretKey` $s \in \mathbb{Z}_p$ 与 $salt \in \{0, 1\}^{32}$。
    * 客户端计算 $P_{pass} = H_p(pass)$，选取随机数 $r \in \mathbb{Z}_p$，记录
      `ClientPRFSession` $\rho = (r, P_{pass}, s)$。
    * 客户端发送 `ClientPRFRequest` $M = r \cdot P_{pass}$。
    * 服务端检索发现用户未注册，返回 `ServerPRFAbsent` 评估值 $N = v \cdot M$。
    * 客户端根据下述逻辑构造 `ClientPRFOverride` $\eta = (salt, E_{pass}, E_{mnem})$ 并提交：
        * 计算 $(H_{pass}, L_{pass}) = \mathrm{PBKDF2}(r^{-1} \cdot N, 2048)$。
        * 构造 $E_{pass} = (s \oplus H_{pass}, H_s(salt, PK, s \oplus H_{pass}, L_{pass}))$。
        * 计算 $(H_{mnem}, L_{mnem}) = \mathrm{PBKDF2}(mnem, 2048)$。
        * 构造 $E_{mnem} = (s \oplus H_{mnem}, H_s(salt, PK, s \oplus H_{mnem}, L_{mnem}))$。

2. **查询与响应阶段**：
    * 口令模式下，用户输入 $pass$。客户端初始化 $\rho = (r, P_{pass}, 0)$，发送
      `ClientPRFRequest` $M = r \cdot H_p(pass)$。
    * 恢复模式下，用户输入助记词 $mnem$ 与拟更新的口令 $pass'$。客户端初始化 $\rho = (r, P_{pass'}, 0)$
      ，发送对应新口令的 $M = r \cdot H_p(pass')$。
    * 服务端根据用户标识检索对应的 $(salt, E_{pass}, E_{mnem})$，计算评估值 $N = v \cdot M$，并下发
      `ServerPRFPresent` $(N, salt, E_{pass}, E_{mnem})$。

3. **还原秘密种子并更新会话**：
    * 客户端首先检查 $e(N, \tilde{G}_{neg}) \cdot e(M, \tilde{V}) \stackrel{?}{=} 1_T$。若失败，则终止流程。
    * 口令模式下，计算 $(H_{pass}, L_{pass}) = \mathrm{PBKDF2}(r^{-1} \cdot N, 2048)$，校验 $E_{pass}$ 并还原 $s$。
    * 恢复模式下，计算 $(H_{mnem}, L_{mnem}) = \mathrm{PBKDF2}(mnem, 2048)$，校验 $E_{mnem}$ 并还原 $s$。
    * 将还原的 $s$ 更新至 $\rho$。若处于恢复模式，客户端需使用当前会话中的 $s$、新口令生成的 $N$ 以及原 $salt$
      重新构造 $E_{pass}$，并通过 `ClientPRFOverride` 消息更新服务端记录。

### B. Pointcheval-Sanders 盲签名授权

1. **权限请求**：客户端计算 `ClientPointCommit` $S = s \cdot G$ 发送给服务端。
2. **角色授予**：服务端确定投票者 $role$（如“选民”），计算 $h_{role} = H_s(role)$。选取随机数 $r \in \mathbb{Z}_p$，返回
   `IdentitySignature` $\sigma = (role, A, B)$：
    * $A = r \cdot G$
    * $B = (h_{role} \cdot w + x) \cdot A + y \cdot (r \cdot S)$
3. **凭证核验**
   ：客户端校验 $e(B, \tilde{G}_{neg}) \cdot e(A, h_{role} \cdot \tilde{W} + \tilde{X} + s \cdot \tilde{Y}) = 1_T$。

### C. 匿名投票证明生成

1. **标识符派生**：针对投票对象 $work$（16 字节 UUID），计算
   `DerivedIdentifier` $ID = s \cdot P_{work}$（$P_{work} = H_p(work)$）。
2. **构造 `IdentityBlindProof`**：包含公开信息 $info$（打分、评语）并对身份合法性进行证明：
    * 选取随机数 $q, r \in \mathbb{Z}_p$。
    * 重随机化签名：$A' = q \cdot A, B' = q \cdot B$。
    * 生成承诺：$Q = r \cdot P_{work}$，$R = e(A', r \cdot \tilde{Y})$。
    * 生成挑战：$c = H_s(PK, H_s(work, ID, info, role, A', B'), Q, R)$。
    * 生成响应：$z = r + c \cdot s \pmod p$。
    * 提交 $\pi = (work, ID, info, role, A', B', c, z)$。

### D. 投票有效性验证

1. **重构验证中间值**：$d' = H_s(work, ID, info, role, A', B')$，$h_{role} = H_s(role)$。
2. **重建承诺**：
    * $Q' = z \cdot P_{work} - c \cdot ID$
    * $R' = e(A', c \cdot h_{role} \cdot \tilde{W} + c \cdot \tilde{X} + z \cdot \tilde{Y}) \cdot e(c \cdot B', \tilde{G}_{neg})$
3. **结果裁定**：检查 $H_s(PK, d', Q', R') \stackrel{?}{=} c$。

### E. 用户手动撤销

1. **提交撤销原语**：用户通过认证信道发送 `ClientRevocation` $\tilde{C} = s \cdot \tilde{G}$。
2. **归属验证**：服务端核验 $e(S, \tilde{G}_{neg}) \cdot e(G, \tilde{C}) = 1_T$。
3. **追踪与清理**：检索数据库中满足 $e(ID, \tilde{G}) \stackrel{?}{=} e(P_{work}, \tilde{C})$ 的所有 $ID$
   ，并撤销对应的 $info$。

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

| 类名                   | 对应方案变量                                              | 字节数 (BLS12-381)                                 |
|:---------------------|:----------------------------------------------------|:------------------------------------------------|
| `ClientPointCommit`  | $S = s \cdot G$                                     | $48$                                            |
| `ClientPRFRequest`   | $M = r \cdot P_{pass}$                              | $48$                                            |
| `ClientPRFSession`   | $\rho = (r, P_{pass}, s)$                           | $112$                                           |
| `ClientPRFOverride`  | $\eta = (salt, E_{pass}, E_{mnem})$                 | $160$                                           |
| `ClientRevocation`   | $\tilde{C} = s \cdot \tilde{G}$                     | $96$                                            |
| `ClientSecretKey`    | $s$                                                 | $32$                                            |
| `DerivedIdentifier`  | $ID = s \cdot P_{work}$                             | $48$                                            |
| `IdentityBlindProof` | $\pi = (work, ID, info, role, A', B', c, z)$        | $224 + \mathrm{len}(role) + \mathrm{len}(info)$ |
| `IdentitySignature`  | $\sigma = (role, A, B)$                             | $96 + \mathrm{len}(role)$                       |
| `ServerPRFAbsent`    | $N = v \cdot M$                                     | $48$                                            |
| `ServerPRFPresent`   | $(N, salt, E_{pass}, E_{mnem})$                     | $208$                                           |
| `ServerPublicKey`    | $PK = (\tilde{V}, \tilde{W}, \tilde{X}, \tilde{Y})$ | $384$                                           |
| `ServerSecretKey`    | $SK = (v, w, x, y)$                                 | $128$                                           |

***

# Anonymous Voting Credentials and ID Derivation Scheme Based on PS Signatures

This scheme is designed for anonymous voting based on BLS12-381 bilinear pairing curves, using a VOPRF mechanism for
collaborative high-entropy secret derivation between the server and user. The issuance phase utilizes rerandomizable
Pointcheval-Sanders blind signatures to grant role-based anonymous credentials, ensuring native unlinkability across
different proof presentations. For 16-byte UUID voting targets, domain-unique but cross-domain decoupled identifiers
are derived, natively preventing double-voting and Sybil attacks. The proof layer encapsulates non-interactive Sigma
protocols into NIZK binary payloads and features a built-in revocation mechanism, allowing the system to guide users
through secure channels to revoke historical vote records.

## 1. Cryptographic Primitives and System Parameters

The scheme is implemented on the pairing-friendly elliptic curve BLS12-381 with a prime order $p$.

* **Bilinear Pairing**: A map $e: \mathbb{G} \times \tilde{\mathbb{G}} \to \mathbb{G}_T$ that satisfies bilinearity,
  non-degeneracy, and computability.
* **Group Generators**:
    * $G$ is the generator of group $\mathbb{G}$.
    * $\tilde{G}$ is the generator of group $\tilde{\mathbb{G}}$.
    * $\tilde{G}_{neg} = (-1) \cdot \tilde{G}$ is the negative generator of $\tilde{\mathbb{G}}$, used for cancellation
      in pairing verification equations.
* **Hash Functions**:
    * $H_p: \{0, 1\}^* \to \mathbb{G}$: Maps an arbitrary string to a point in $\mathbb{G}$ (Hash-to-Curve).
    * $H_s: \{0, 1\}^* \to \mathbb{Z}_p$: Maps an arbitrary string to a scalar in $\mathbb{Z}_p$ (Hash-to-Scalar).
* **Auxiliary Functions**:
    * $\oplus$: Bitwise XOR over equal-length byte strings.
    * $\mathrm{PBKDF2}(\textit{input}, \textit{iters})$: A password-based key derivation function; split its output into
      two halves denoted as $(H, L)$.
* **Server Key Pair**:
    * **Private Key ($SK$):** A tuple of random scalars $(v, w, x, y) \in \mathbb{Z}_p^4$.
    * **Public Key ($PK$):** A tuple of points in $\tilde{\mathbb{G}}$ calculated
      as: $PK = (\tilde{V}, \tilde{W}, \tilde{X}, \tilde{Y}) = (v \cdot \tilde{G}, w \cdot \tilde{G}, x \cdot \tilde{G}, y \cdot \tilde{G})$.

## 2. Scheme Process Flow

### A. Account Initialization and Secret Seed Derivation Based on VOPRF

1. **Initial Request and Envelope Submission**:
    * Client generates a random `ClientSecretKey` $s \in \mathbb{Z}_p$ and a random $salt \in \{0, 1\}^{32}$.
    * Client computes $P_{pass} = H_p(pass)$, picks a random $r \in \mathbb{Z}_p$, and records
      `ClientPRFSession` $\rho = (r, P_{pass}, s)$.
    * Client sends `ClientPRFRequest` $M = r \cdot P_{pass}$.
    * Server determines that the user is not registered and returns `ServerPRFAbsent` with the evaluation
      $N = v \cdot M$.
    * Client constructs `ClientPRFOverride` $\eta = (salt, E_{pass}, E_{mnem})$ as follows and submits it:
        * Compute $(H_{pass}, L_{pass}) = \mathrm{PBKDF2}(r^{-1} \cdot N, 2048)$.
        * Construct $E_{pass} = (s \oplus H_{pass}, H_s(salt, PK, s \oplus H_{pass}, L_{pass}))$.
        * Compute $(H_{mnem}, L_{mnem}) = \mathrm{PBKDF2}(mnem, 2048)$.
        * Construct $E_{mnem} = (s \oplus H_{mnem}, H_s(salt, PK, s \oplus H_{mnem}, L_{mnem}))$.

2. **Query and Response**:
    * In password mode, user inputs $pass$. Client initializes $\rho = (r, P_{pass}, 0)$ and sends
      `ClientPRFRequest` $M = r \cdot H_p(pass)$.
    * In recovery mode, user inputs the mnemonic $mnem$ and a new password $pass'$. Client initializes
      $\rho = (r, P_{pass'}, 0)$ and sends $M = r \cdot H_p(pass')$ for the new password.
    * Server looks up $(salt, E_{pass}, E_{mnem})$ for the user identifier, computes $N = v \cdot M$, and returns
      `ServerPRFPresent` $(N, salt, E_{pass}, E_{mnem})$.

3. **Secret Seed Recovery and Session Update**:
    * Client first checks $e(N, \tilde{G}_{neg}) \cdot e(M, \tilde{V}) \stackrel{?}{=} 1_T$. Abort on failure.
    * In password mode, compute $(H_{pass}, L_{pass}) = \mathrm{PBKDF2}(r^{-1} \cdot N, 2048)$, verify $E_{pass}$,
      and recover $s$.
    * In recovery mode, compute $(H_{mnem}, L_{mnem}) = \mathrm{PBKDF2}(mnem, 2048)$, verify $E_{mnem}$, and recover
      $s$.
    * Update $\rho$ with the recovered $s$. In recovery mode, the client reconstructs $E_{pass}$ using the current
      session's $s$, the new-password-derived $N$, and the original $salt$, then updates the server record via
      `ClientPRFOverride`.

### B. Pointcheval-Sanders Blind Signature Issuance

1. **Request**: Client computes `ClientPointCommit` $S = s \cdot G$ and sends it to the server.
2. **Authorization**: Server determines voter $role$, computes $h_{role} = H_s(role)$. Select a
   random $r \in \mathbb{Z}_p$, and return `IdentitySignature` $\sigma = (role, A, B)$:
    * $A = r \cdot G$
    * $B = (h_{role} \cdot w + x) \cdot A + y \cdot (r \cdot S)$
3. **Credential Validation**: Client
   verifies $e(B, \tilde{G}_{neg}) \cdot e(A, h_{role} \cdot \tilde{W} + \tilde{X} + s \cdot \tilde{Y}) = 1_T$.

### C. Anonymous Voting Proof Generation

1. **Identifier Derivation**: For a target $work$ (16-byte UUID), compute
   `DerivedIdentifier` $ID = s \cdot P_{work}$ ($P_{work} = H_p(work)$).
2. **Construct `IdentityBlindProof`**: Include public data $info$ (scores, comments) and generate a ZKP:
    * Select random numbers $q, r \in \mathbb{Z}_p$.
    * Re-randomize signature: $A' = q \cdot A, B' = q \cdot B$.
    * Compute commitments: $Q = r \cdot P_{work}$, $R = e(A', r \cdot \tilde{Y})$.
    * Compute challenge: $c = H_s(PK, H_s(work, ID, info, role, A', B'), Q, R)$.
    * Compute response: $z = r + c \cdot s \pmod p$.
    * Submit $\pi = (work, ID, info, role, A', B', c, z)$.

### D. Verification of Vote Validity

1. **Reconstruct Intermediate Values**: $d' = H_s(work, ID, info, role, A', B')$ and $h_{role} = H_s(role)$.
2. **Reconstruct Commitments**:
    * $Q' = z \cdot P_{work} - c \cdot ID$
    * $R' = e(A', c \cdot h_{role} \cdot \tilde{W} + c \cdot \tilde{X} + z \cdot \tilde{Y}) \cdot e(c \cdot B', \tilde{G}_{neg})$
3. **Decision**: Check if $H_s(PK, d', Q', R') \stackrel{?}{=} c$.

### E. Manual User Revocation

1. **Submit Revocation Token**: User sends `ClientRevocation` $\tilde{C} = s \cdot \tilde{G}$ through a trusted channel.
2. **Attribution Verification**: Server verifies $e(S, \tilde{G}_{neg}) \cdot e(G, \tilde{C}) = 1_T$.
3. **Trace & Cleanup**: Search for all $ID$ satisfying $e(ID, \tilde{G}) \stackrel{?}{=} e(P_{work}, \tilde{C})$ and
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

| Class Name           | Scheme Variable                                     | Bytes (BLS12-381)                               |
|:---------------------|:----------------------------------------------------|:------------------------------------------------|
| `ClientPointCommit`  | $S = s \cdot G$                                     | $48$                                            |
| `ClientPRFRequest`   | $M = r \cdot P_{pass}$                              | $48$                                            |
| `ClientPRFSession`   | $\rho = (r, P_{pass}, s)$                           | $112$                                           |
| `ClientPRFOverride`  | $\eta = (salt, E_{pass}, E_{mnem})$                 | $160$                                           |
| `ClientRevocation`   | $\tilde{C} = s \cdot \tilde{G}$                     | $96$                                            |
| `ClientSecretKey`    | $s$                                                 | $32$                                            |
| `DerivedIdentifier`  | $ID = s \cdot P_{work}$                             | $48$                                            |
| `IdentityBlindProof` | $\pi = (work, ID, info, role, A', B', c, z)$        | $224 + \mathrm{len}(role) + \mathrm{len}(info)$ |
| `IdentitySignature`  | $\sigma = (role, A, B)$                             | $96 + \mathrm{len}(role)$                       |
| `ServerPRFAbsent`    | $N = v \cdot M$                                     | $48$                                            |
| `ServerPRFPresent`   | $(N, salt, E_{pass}, E_{mnem})$                     | $208$                                           |
| `ServerPublicKey`    | $PK = (\tilde{V}, \tilde{W}, \tilde{X}, \tilde{Y})$ | $384$                                           |
| `ServerSecretKey`    | $SK = (v, w, x, y)$                                 | $128$                                           |
