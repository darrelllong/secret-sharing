# Theory of the Implemented Schemes

This file records the algebra behind the schemes implemented by this
crate. It is intentionally implementation-facing: the statements below
match the public modules in `src/`, not just the abstract papers in
`bib/references.bib`.

All field-based proofs below are conditional on the modulus actually
being prime, so arithmetic is in
$F = \mathbb{F}_p$. The safe constructor `PrimeField::new` validates
primality with Miller-Rabin; `PrimeField::new_unchecked` only checks
$p > 1$ and relies on the caller's proof that $p$ is prime. With a
composite modulus, inverses may not exist and the interpolation,
linear-algebra, and privacy proofs below do not apply. Trustee labels
are assumed to be distinct non-zero field elements, user-supplied field
values are meant as representatives modulo $p$, and random values are
assumed to be sampled uniformly from the stated domain. The Rust
implementation uses variable-time `BigUint` arithmetic, so these are
information-theoretic statements about the mathematical schemes, not
side-channel claims about a particular deployment.

For a perfect secret-sharing scheme with secret $S$ and shares $V_i$,
an unauthorized coalition $C$ has perfect privacy when

$$
\mathrm{Pr}[S = s \mid V_C = v] = \mathrm{Pr}[S = s]
$$

for every secret value $s$ and every possible view $v$ of that
coalition. Equivalently,

$$
I(S; V_C) = 0.
$$

Some implemented primitives are ramp schemes, statistically secure CRT
schemes, computational VSS schemes, visual-cryptography schemes,
proactive refresh layers, reconstruction-uniqueness schemes, or
erasure-coding helpers. Those sections say so explicitly.

## `trivial`: Karnin-Greene-Hellman Additive $n$-of-$n$

Reference: `karnin1983secret`.

### Construction

For a field secret $s \in F$, sample
$v_1,\ldots,v_{n-1} \leftarrow F$ uniformly and set

$$
v_n = s - \sum_{i=1}^{n-1} v_i.
$$

Every player receives one value $v_i$. The byte-string XOR variant is
the same construction over bit vectors with addition equal to XOR.

### Correctness

All $n$ shares recover the secret by addition:

$$
\sum_{i=1}^{n} v_i
= \sum_{i=1}^{n-1} v_i + s - \sum_{i=1}^{n-1} v_i
= s.
$$

### Perfect Privacy

Let a coalition see any $n - 1$ shares and miss share $j$. For every
candidate secret $s'$, there is exactly one value of the missing share
that makes the visible shares consistent:

$$
v_j = s' - \sum_{i \neq j} v_i.
$$

Because the omitted share is uniform from the coalition's point of
view, the visible distribution is the same for every $s'$. Therefore
any strict subset of the players has zero information about the secret.

### Caveats

This is only an $n$-of-$n$ scheme. It cannot express a threshold
$k < n$. Supplying $n = 1$ would publish the secret, so the
implementation rejects it.

## `shamir`: Shamir Polynomial $(k, n)$

Reference: `shamir1979share`.

### Construction

Choose a random polynomial of degree less than $k$:

$$
q(x) = \bar{s} + a_1 x + a_2 x^2 + \cdots + a_{k-1} x^{k-1},
$$

where $\bar{s}$ is the field element being shared and
$a_1,\ldots,a_{k-1}$ are uniform in $F$. In the public Rust API,
`split` sets $\bar{s} = \texttt{secret} \bmod p$. Player $i$ receives

$$
(x_i, q(x_i)).
$$

The crate uses $x_i = i$ and requires $p > n$.

### Correctness

Any $k$ shares give $k$ distinct points on a degree $< k$ polynomial.
Lagrange interpolation recovers the unique polynomial:

$$
q(x) = \sum_{i=1}^{k} y_i
\prod_{\substack{1 \le j \le k \\ j \neq i}}
\frac{x - x_j}{x_i - x_j}.
$$

Evaluating at zero gives the field secret

$$
\bar{s} = q(0).
$$

### Perfect Privacy

Let $T$ be any set of $t < k$ shares. Fix any candidate secret $s'$ and
consider the affine space of coefficient vectors
$(a_1,\ldots,a_{k-1})$ satisfying the $t$ share equations and
$q(0) = s'$. These are $t + 1$ independent linear equations in $k$
unknown coefficients, so the number of solutions is

$$
p^{k - t - 1}.
$$

This count is independent of $s'$. Since the original coefficients are
uniform, the coalition's view has the same probability under every
candidate secret. Thus every coalition of size at most $k - 1$ has
perfect privacy.

### Caveats

The field must contain at least $n + 1$ distinct elements: zero for the
secret point and $n$ non-zero share labels. If the caller wants to
recover an integer secret exactly, rather than its residue class, the
secret must satisfy $\texttt{secret} < p$; otherwise the module
reconstructs $\texttt{secret} \bmod p$. The implementation also rejects
duplicate labels and validates extra shares, but exactly $k$ tampered
shares can still interpolate to a wrong secret. Use `vss` or an
authentication layer when shareholders may be malicious.

## `bytes`: Chunked Byte-String Shamir

Reference: `shamir1979share`.

### Construction

The byte module is Shamir applied independently to field-sized blocks.
For a modulus $p$, it chooses a plaintext block length

$$
b = \left\lfloor \frac{\mathrm{bits}(p) - 1}{8} \right\rfloor
$$

so every block is an integer strictly below $p$. Each block becomes a
separate Shamir secret with the same trustee labels.

### Correctness

Each block is recovered by Shamir interpolation. Concatenating the
recovered blocks and truncating to the stored original byte length gives
the original byte string.

### Perfect Privacy

For each block $B_j$, Shamir gives

$$
I(B_j; V_C^{(j)}) = 0
$$

for every coalition $|C| < k$. Independent randomness is used for each
block, so the joint view is a product distribution independent of the
block vector:

$$
I((B_1,\ldots,B_m); V_C^{(1)},\ldots,V_C^{(m)}) = 0.
$$

### Caveats

The serialized shares reveal metadata: version, trustee label, and the
original byte length. This is not an all-or-nothing transform or file
encryption format; it protects the payload bytes under the same passive
threshold model as Shamir. The wire format supports labels only up to
255.

## `shamir::split_multi`: KGH Multi-Secret Coefficient Packing

Reference: `karnin1983secret`.

### Construction

Pack $\ell \le k$ field secrets into the low coefficients of one
degree $< k$ polynomial:

$$
q(x) = s_0 + s_1 x + \cdots + s_{\ell-1} x^{\ell-1} + a_{\ell} x^{\ell} + \cdots + a_{k-1} x^{k-1}.
$$

The coefficients $a_{\ell},\ldots,a_{k-1}$ are random. Player $i$
receives $(x_i, q(x_i))$.

### Correctness

Any $k$ shares interpolate $q$. The first $\ell$ coefficients of the
interpolated polynomial are exactly

$$
(s_0,\ldots,s_{\ell-1}).
$$

### Privacy and Leakage

This is a ramp-style packing, not a free way to get $\ell$ independent
Shamir secrets with threshold $k$.

For a coalition of size $t$, fixing all $\ell$ secrets leaves
$k - \ell$ random coefficients. The coalition imposes $t$ linear
constraints. Full perfect privacy for the whole secret vector holds
whenever

$$
t \le k - \ell.
$$

In that range, every candidate secret vector has the same number of
compatible random paddings:

$$
p^{k - \ell - t}.
$$

For larger coalitions, the shares reveal linear information about the
packed coefficients. In particular, $k - 1$ shares leave only a
one-dimensional affine line of possible coefficient vectors. Whether a
particular low coefficient still varies on that line depends on the
share labels and field; this API does not check the stronger
matrix/projection condition used in the general KGH theorem. The safe
claim for this coefficient-packing implementation is the ramp bound
above.

### Caveats

Use ordinary `shamir` independently for each secret if every group of
$k - 1$ players must learn nothing jointly about the whole vector. Use
this packing only when the ramp trade-off is acceptable or when the
adversary size is bounded by $k - \ell$.

## `kgh`: Karnin-Greene-Hellman Matrix Scheme

Reference: `karnin1983secret`.

### Construction

Let the secret be a vector $s \in F^m$. Form

$$
u = (u_0,u_1,\ldots,u_{k-1}),
$$

where $u_0 = s$ and each $u_j \in F^m$ for $j \ge 1$ is uniform. The
paper's matrix scheme gives player $i$

$$
v_i = u A_i.
$$

The crate instantiates the public matrix bank with the Vandermonde
construction. Equivalently, for each vector coordinate $c$,

$$
v_i[c] = \sum_{j=0}^{k-1} u_j[c] x_i^j.
$$

Thus each coordinate is an independent Shamir sharing with the same
labels.

### Correctness

For any $k$ players, each coordinate gives $k$ evaluations of a degree
$< k$ polynomial. Interpolating coordinate-wise recovers

$$
u_0[c] = s[c]
$$

for every $c = 1,\ldots,m$.

### Perfect Privacy

For a coalition of size $t < k$, each coordinate has Shamir privacy:

$$
I(s[c]; V_C[c]) = 0.
$$

The coordinates use independent random padding, so the whole vector is
also hidden:

$$
I(s; V_C) = 0.
$$

### Caveats

The implemented Vandermonde bank needs $p > n$. Shares are vector
shares, so each player stores $m$ field elements. The implementation is
passive-secure; exactly $k$ bad vector shares can solve to the wrong
secret.

## `kothari`: Generalized Linear Threshold Scheme

Reference: `kothari1984generalized`.

### Construction

Let $A \in F^{k \times n}$ be public. The secret-bearing vector is

$$
u = (s,r_2,\ldots,r_k),
$$

with $r_2,\ldots,r_k$ uniform. Player $i$ receives the scalar

$$
v_i = u A_i,
$$

where $A_i$ is column $i$ of $A$.

### Correctness

For a qualified set $T$ of $k$ columns, write $A_T$ for the
$k \times k$ submatrix and $v_T$ for the corresponding share row
vector. If $A_T$ is invertible, then

$$
u = v_T A_T^{-1}.
$$

The recovered secret is the first coordinate of $u$.

The `vandermonde` constructor chooses

$$
A_{j,i} = x_i^{j-1},
$$

which reduces to Shamir.

### Perfect Privacy

For a coalition $T$ with $t < k$, split the selected matrix rows as

$$
A_T =
\begin{bmatrix}
a_T \\
B_T
\end{bmatrix},
$$

where $a_T$ is the first row restricted to $T$ and $B_T$ contains the
remaining $k - 1$ rows. The coalition sees

$$
v_T = s a_T + r B_T.
$$

This view is independent of $s$ exactly when

$$
a_T \in \mathrm{rowspan}(B_T).
$$

If this holds, choose $\lambda$ with $\lambda B_T = a_T$. Then

$$
v_T = (r + s\lambda)B_T.
$$

The map $r \mapsto r + s\lambda$ is a bijection of $F^{k-1}$, so
uniform $r$ gives the same distribution for every $s$.

Conversely, if $a_T$ is not in the row span of $B_T$, there exists a
column vector $c$ with $B_T c = 0$ but $a_T c \ne 0$. The coalition can
compute

$$
v_T c = s(a_T c),
$$

which determines $s$. Thus the row-span condition is necessary and
sufficient for perfect privacy of that coalition.

For the Vandermonde specialization, this condition holds for every
$t < k$: for any selected non-zero labels, there is a polynomial
$g(x)$ with $g(0)=0$ and $g(x_i)=1$ on those $t$ labels, using degree
at most $k - 1$. That polynomial expresses the all-ones first row as a
linear combination of the lower Vandermonde rows on $T$.

### Caveats

The general `LinearScheme::new` API trusts the caller's matrix. The
provided `new_checked` verifies the reconstruction condition that every
$k$ columns are independent, but that condition alone does not imply
privacy. A matrix with a column equal to the first basis vector would
leak $s$ in that one share while still possibly allowing many
$k$-column sets to reconstruct. For secrecy, use `vandermonde` or
verify the row-span privacy condition above for all unauthorized
coalitions.

## `blakley`: Geometric Hyperplane Scheme

Reference: `blakley1979safeguarding`.

### Construction

Choose a point

$$
P = (s,r_1,\ldots,r_{k-1}) \in F^k
$$

with random tail coordinates. A share is a hyperplane through $P$:

$$
a_1 y_1 + a_2 y_2 + \cdots + a_{k-1} y_{k-1} + y_k = b.
$$

The implementation samples $a_1,\ldots,a_{k-1}$ uniformly and sets
$b$ so the equation holds at $P$.

### Correctness

Any $k$ hyperplanes give a linear system

$$
H P^T = b.
$$

If $H$ is invertible, Gaussian elimination recovers $P$, and the
secret is the first coordinate.

### Perfect Privacy

For $t < k$ hyperplanes, the coalition sees

$$
b_T = s a_T + R B_T,
$$

where $R = (r_1,\ldots,r_{k-1})$. If the coefficient matrix $B_T$ on
the random coordinates has full row rank, then $R B_T$ is uniform over
$F^t$. Adding the fixed shift $s a_T$ does not change the distribution,
so the view is independent of $s$.

Geometrically, the $t$ hyperplanes leave an affine subspace of possible
points. Under the full-rank condition above, its projection onto the
secret coordinate is all of $F$.

### Caveats

The implementation rejection-samples only while building the first
$k$ hyperplanes, so the common reconstruction path from the first
$k$ generated shares is guarded against singularity. It does not force
every possible $k$-subset, or every unauthorized random-coordinate
matrix, into general position. Reconstruction from an arbitrary
$k$-subset can still fail if that subset is singular, and privacy
against a particular unauthorized set relies on the random-coordinate
matrix for that set having full row rank. These failures occur with
small probability for large $p$, but they are not impossible. Use
Shamir or KGH when deterministic MDS-style threshold guarantees are
required.

## `blakley_meadows`: Geometric $(k, L, n)$ Ramp Scheme

Reference: `blakley1984ramp`.

### Construction

This is the ramp version of Blakley's geometric scheme. Let the secret
be

$$
s = (s_1,\ldots,s_L) \in F^L
$$

with $1 \le L < k$. Choose a point

$$
P = (s_1,\ldots,s_L,r_{L+1},\ldots,r_k) \in F^k,
$$

where the last $k - L$ coordinates are uniform random padding. A share
is a random hyperplane through $P$:

$$
a_1 y_1 + a_2 y_2 + \cdots + a_{k-1} y_{k-1} + y_k = b.
$$

The implementation samples $a_1,\ldots,a_{k-1}$ uniformly and sets
$b$ so the equation holds at $P$.

### Correctness

Any $k$ hyperplanes give a linear system

$$
H P^T = b.
$$

When $H$ is invertible, solving the system recovers the whole point
$P$, and the first $L$ coordinates are the secret vector.

### Ramp Privacy

For $t$ observed hyperplanes, the coalition has $t$ linear equations in
the $k$ point coordinates. If $t \le k - L$ and the submatrix on the
random padding coordinates has full row rank, then the random padding
maps onto all of $F^t$. The coalition's view is therefore a uniform
shift independent of

$$
(s_1,\ldots,s_L).
$$

For $k - L < t < k$, the intersection of the observed hyperplanes has
dimension $k - t$, so it cannot project onto all $L$ secret
coordinates. Those intermediate coalitions learn partial linear
information, exactly the ramp trade-off studied by Blakley and
Meadows.

### Caveats

The implementation rejects $L = k$ because there would be no padding.
Like `blakley`, it rejection-samples the first $k$ generated
hyperplanes until that leading reconstruction matrix is nonsingular,
but it does not force every possible submatrix into general position.
Reconstruction from another $k$-subset can fail if that subset is
singular, and exactly $k$ tampered shares can solve to a wrong secret.
Use extras for consistency checks, or use a verifiable layer when
parties are malicious.

## `mignotte`: CRT Reconstruction-Uniqueness Scheme

Reference: `mignotte1983secret`.

### Construction

Choose pairwise coprime integers

$$
m_1 < m_2 < \cdots < m_n
$$

with

$$
\alpha = \prod_{i=n-k+2}^{n} m_i,
$$

the product of the $k - 1$ largest moduli, and

$$
\beta = \prod_{i=1}^{k} m_i,
$$

the product of the $k$ smallest moduli. A Mignotte sequence satisfies

$$
\alpha < \beta.
$$

The secret must lie in the open interval

$$
\alpha < S < \beta.
$$

Player $i$ receives

$$
(i, S \bmod m_i).
$$

### Correctness

Any $k$ shares have modulus product at least $\beta$. By the Chinese
Remainder Theorem, the residues determine a unique value modulo that
product. Since the legal secret lies below $\beta$, that CRT solution
has a unique representative in the legal interval, which is $S$.

### Secrecy Status

Mignotte is not perfectly secret. A coalition with moduli product $P$
learns

$$
S \bmod P.
$$

The possible secrets are only

$$
\{x : \alpha < x < \beta, x \equiv S \pmod P\}.
$$

This candidate set is much smaller than the original interval and its
size depends on the observed residue. Therefore, in general,

$$
I(S; V_C) > 0.
$$

### Caveats

Use Mignotte only when reconstruction uniqueness is enough and leakage
below threshold is acceptable. It is not a perfect or statistical
secret-sharing scheme. It also has no built-in authentication; exactly
$k$ tampered residues can CRT-reconstruct to a wrong in-range value.

## `asmuth_bloom`: CRT Scheme With Statistical Secrecy

Reference: `asmuth1983modular`.

### Construction

Choose a public secret modulus $m_0$ and pairwise coprime moduli

$$
m_1 < m_2 < \cdots < m_n
$$

with each $m_i$ coprime to $m_0$. Define

$$
M_{\mathrm{bot}} = \prod_{i=1}^{k} m_i
$$

and

$$
M_{\mathrm{top}} = \prod_{i=n-k+2}^{n} m_i.
$$

The Asmuth-Bloom condition is

$$
m_0 M_{\mathrm{top}} < M_{\mathrm{bot}}.
$$

For a secret $S \in \{0,\ldots,m_0-1\}$, sample

$$
A \leftarrow \{0,\ldots,\lfloor M_{\mathrm{bot}} / m_0 \rfloor - 1\}
$$

and set

$$
y = S + A m_0.
$$

Player $i$ receives

$$
(i, y \bmod m_i).
$$

### Correctness

Any $k$ shares have modulus product at least $M_{\mathrm{bot}}$. Since
$y < M_{\mathrm{bot}}$, the CRT reconstruction from any $k$ shares
recovers $y$ exactly. Then

$$
S = y \bmod m_0.
$$

### Statistical Privacy

Let an unauthorized coalition have modulus product $P$. Then
$P \le M_{\mathrm{top}}$. The coalition learns

$$
y \equiv r \pmod P.
$$

For a fixed secret $S$, this condition is

$$
S + A m_0 \equiv r \pmod P.
$$

Because $\mathrm{gcd}(m_0,P)=1$, this picks exactly one residue class for
$A \bmod P$. Put

$$
N = \left\lfloor M_{\mathrm{bot}}/m_0 \right\rfloor.
$$

Over the interval $0 \le A < N$, the number of solutions in each
residue class modulo $P$ is either $\lfloor N/P \rfloor$ or
$\lceil N/P \rceil$. Thus the coalition's view is statistically close
to independent of $S$: changing $S$ only permutes which residues get
the extra one count, so the total variation distance between two
candidate-secret views is at most $P/N$.

The inequality $m_0 P < M_{\mathrm{bot}}$ gives $P < M_{\mathrm{bot}}/m_0$,
so the mask interval contains at least one complete period modulo every
unauthorized product $P$.

### Caveats

This crate's parameterization gives statistical, generally not exact,
perfect secrecy unless the mask range is a multiple of every
unauthorized product. If exact perfect privacy is required, use Shamir.
As with other unauthenticated CRT schemes, exactly $k$ tampered shares
may reconstruct a wrong secret.

## `ramp`: McEliece-Sarwate Reed-Solomon Ramp

Reference: `mceliece1981sharing`.

### Construction

The secret is a vector

$$
b = (b_1,\ldots,b_k) \in F^k.
$$

Let $P(x)$ be the unique polynomial of degree less than $k$ with

$$
P(j) = b_j
$$

for $j = 1,\ldots,k$. For shares produced by `split`, player $i$
receives

$$
(k+i, P(k+i)).
$$

### Correctness

Any $k$ valid shares generated with those public labels interpolate
$P$. Evaluating at the secret slots recovers

$$
(P(1),\ldots,P(k)) = (b_1,\ldots,b_k).
$$

### Ramp Privacy

A coalition of $t < k$ generated shares evaluates the degree $< k$
polynomial at $t$ public points outside the secret anchor slots. The
Reed-Solomon evaluation map from the $k$ anchor values to those $t$
share values has rank $t$, so the coalition learns $t$ independent
linear constraints on the $k$-element secret vector. Therefore the
number of secret vectors compatible with any observed view is

$$
p^{k-t}.
$$

For $t = k - 1$, the coalition narrows the secret to
$p$ possible vectors. This is information-theoretic leakage, but not
full recovery.

### Caveats

This is a ramp/data-compressed scheme, not a perfect threshold scheme.
It should not be used where every group of fewer than $k$ players must
learn nothing. Its benefit is storage rate: one field element per share
protects a $k$-field-element secret with partial privacy.

The correctness and privacy statements assume labels outside the secret
anchor slots. Shares produced by `split` use $k+1,\ldots,k+n$, and
`ramp::reconstruct` rejects labels that reduce to zero or to one of the
reserved anchor positions $1,\ldots,k$. It does not authenticate share
values or validate extras beyond the first $k$ points, so exactly
$k$ forged non-anchor shares can interpolate to a wrong secret vector.
Validate share authenticity outside this module when callers are
untrusted.

## `yamamoto`: $(k, L, n)$ Ramp Scheme

Reference: `yamamoto1986secret`.

### Construction

Let the secret be

$$
s = (s_1,\ldots,s_L) \in F^L
$$

with $1 \le L \le k$. Choose random padding values
$u_{L+1},\ldots,u_k$. Let $P(x)$ be the unique degree $< k$ polynomial
such that

$$
P(j) = s_j \quad \text{for } 1 \le j \le L
$$

and

$$
P(j) = u_j \quad \text{for } L < j \le k.
$$

For shares produced by `split`, player $i$ receives

$$
(k+i, P(k+i)).
$$

### Correctness

Any $k$ valid shares generated with those public labels interpolate
$P$. Reading the first $L$ anchor positions recovers

$$
(P(1),\ldots,P(L)) = (s_1,\ldots,s_L).
$$

### Ramp Privacy

The random padding has dimension $k - L$. By the MDS property of the
underlying Reed-Solomon code, any $t \le k - L$ share evaluations can
be matched by exactly

$$
p^{k-L-t}
$$

padding vectors for every fixed secret. Therefore those coalitions have
perfect privacy.

For $k - L < t < k$, the coalition learns $t - (k - L)$ independent
linear constraints about the $L$ secret symbols. Full recovery still
requires $k$ shares.

### Caveats

Only the $L = 1$ case has Shamir-style privacy against every
$k - 1$-sized unauthorized coalition. The $L = k$ case is the
McEliece-Sarwate ramp scheme and gives no nontrivial perfect-privacy
threshold. Use parameters with care: increasing $L$ improves rate and
decreases privacy.

The proof assumes share labels are outside the reserved anchor slots
$1,\ldots,k$. The implementation rejects zero labels, labels colliding
with those anchors, duplicate labels, and inconsistent extras. It does
not authenticate shares, so exactly $k$ forged non-anchor shares can
still interpolate to a wrong secret. It is not an active-security
protocol.

## `ito`: Ito-Saito-Nishizeki Cumulative Array

Reference: `ito1989secret`.

### Construction

Let the access structure be monotone and let

$$
F_1,\ldots,F_t
$$

be its maximal forbidden coalitions. A coalition $Q$ is qualified
exactly when

$$
Q \nsubseteq F_i
$$

for every $i$.

Choose $r_1,\ldots,r_{t-1}$ uniformly and set

$$
r_t = s - \sum_{i=1}^{t-1} r_i.
$$

Player $j$ receives every $r_i$ for which $j \notin F_i$.

### Correctness

If $Q$ is qualified, then for every $i$ there is some player
$j \in Q$ with $j \notin F_i$. Thus the coalition obtains every
$r_i$. Summing gives

$$
\sum_{i=1}^{t} r_i = s.
$$

### Perfect Privacy

If $Q$ is forbidden, then by maximality and monotonicity it is contained
in some maximal forbidden set $F_j$. No player in $Q$ receives $r_j$.

The visible values are an additive sharing with at least one missing
summand. For every candidate secret $s'$, there is exactly one value of
the missing $r_j$ that makes the visible values sum to $s'$. Since that
missing value is uniform from the coalition's point of view, the view
is independent of $s$.

### Caveats

The cumulative-array representation can be exponentially large. For a
threshold $(k, n)$ access structure it uses one component for every
$(k - 1)$-subset of players. The scheme is not error-correcting:
minimal qualified coalitions often have no duplicate copy of a
sub-share, so tampering can produce a wrong secret.

## `benaloh_leichter`: Monotone Formula Secret Sharing

Reference: `benaloh1990generalized`.

### Construction

The access structure is a monotone Boolean formula. Distribution walks
the formula from the root:

- At an `OR` node, give the same value to every child.
- At an `AND` node with $m$ children, sample
  $z_1,\ldots,z_{m-1}$ uniformly and set

$$
z_m = x - \sum_{i=1}^{m-1} z_i.
$$

- At a leaf, give the current value to that leaf's player.

### Correctness

Correctness follows by induction on the formula tree.

At an `OR` node, any satisfied child reconstructs the node value. At an
`AND` node, every child reconstructs its additive piece, and summing
those pieces gives the node value:

$$
\sum_{i=1}^{m} z_i = x.
$$

Thus any coalition satisfying the formula reconstructs the root secret,
assuming the supplied fragments are the authentic fragments generated
for those formula leaves.

### Perfect Privacy

Privacy is also by induction. A false leaf gives no value to the
coalition. A false `OR` node has all children false, and each child view
hides the replicated node value. A false `AND` node has at least one
false child; the missing child piece is a one-time pad for the node
value, so the visible child pieces have the same distribution for every
candidate node value.

Therefore any coalition that does not satisfy the formula has a view
independent of the root secret.

### Caveats

This scheme is efficient only when the access structure has a succinct
monotone formula. It is not an active-security protocol. The
implementation rejects direct contradictions at the same leaf path, but
an OR branch with internally tampered fragments can reconstruct to a
wrong value before another valid branch is considered.

The `reconstruct` API checks duplicate player IDs, contradictory
values for the same path, and whether every submitted fragment path is
actually a leaf labelled by the submitting `PlayerShare.player`. That
path-ownership check prevents a caller from satisfying the formula by
attaching another player's leaf path to its own share. This is still
not active security: a player can tamper with a value on a path it
legitimately owns, and an OR branch with an internally corrupted but
syntactically valid subtree can produce a wrong value before another
valid branch is considered.

## `karchmer_wigderson`: Monotone Span Program

Reference: `karchmer1993span`.

### Construction

A monotone span program consists of a matrix

$$
M \in F^{d \times m}
$$

with row labels $\rho(j)$ assigning each row to a player, and target
vector

$$
e_1 = (1,0,\ldots,0).
$$

The mathematical construction requires $m \ge 1$ so that this target
exists.

To share $s$, sample

$$
w = (s,r_2,\ldots,r_m)
$$

and give row owner $\rho(j)$ the value

$$
\langle M_j, w \rangle.
$$

A coalition is qualified when $e_1$ lies in the span of its labelled
rows.

### Correctness

If coalition $C$ is qualified, there are coefficients $c_j$ such that

$$
\sum_{\rho(j) \in C} c_j M_j = e_1.
$$

Applying the same coefficients to the share values gives

$$
\sum_{\rho(j) \in C} c_j \langle M_j, w \rangle
= \left\langle \sum_{\rho(j) \in C} c_j M_j, w \right\rangle
= \langle e_1, w \rangle
= s.
$$

### Perfect Privacy

If $C$ is unqualified, then $e_1$ is not in the row span of $M_C$.
By linear algebra, there exists a vector $z$ such that

$$
M_C z = 0
$$

but

$$
\langle e_1, z \rangle \neq 0.
$$

Scaling $z$ changes the first coordinate of $w$ by any desired amount
while leaving all shares held by $C$ unchanged. This gives a bijection
between random choices consistent with secret $s$ and random choices
consistent with any other secret $s'$. Hence the coalition's view is
independent of the secret.

### Caveats

The access structure is exactly the one induced by the supplied span
program. The constructor checks shape, enforces positive row width, and
rejects player label zero; it does not prove that the program
represents some intended external policy. Reconstruction is passive:
forged fragments for rows legitimately owned by a qualified coalition
can make that coalition compute a wrong value unless the caller adds
verification.

## `brickell`: Ideal Vector-Space Secret Sharing

Reference: `brickell1989ideal`.

### Construction

Brickell's scheme is the one-row-per-player specialization of the
monotone span-program construction. Publish a target vector

$$
t = e_1
$$

with $m \ge 1$, and one vector $v_j \in F^m$ for each player. To share
$s$, choose

$$
u = (s,r_2,\ldots,r_m)
$$

with random tail coordinates. Player $j$ receives one field element:

$$
w_j = \langle v_j, u \rangle.
$$

A coalition $C$ is qualified exactly when

$$
t \in \mathrm{span}\{v_j : j \in C\}.
$$

### Correctness

If $C$ is qualified, there are coefficients $c_j$ such that

$$
\sum_{j \in C} c_j v_j = t.
$$

Applying those coefficients to the shares gives

$$
\sum_{j \in C} c_j w_j
= \left\langle \sum_{j \in C} c_j v_j, u \right\rangle
= \langle t,u \rangle
= s.
$$

### Perfect Privacy

If $C$ is unqualified, then $t$ is not in the span of the coalition's
vectors. Therefore there exists a vector $z$ with

$$
\langle v_j,z\rangle = 0 \quad \text{for all } j \in C
$$

but

$$
\langle t,z\rangle \neq 0.
$$

Adding a scalar multiple of $z$ to $u$ changes the secret coordinate
while leaving every share held by $C$ unchanged. This gives the same
bijection proof as the span-program construction: every view compatible
with one secret is compatible with every other secret in the same
number of ways.

### Caveats

The scheme is ideal: every player stores one field element. Not every
monotone access structure has such an ideal realization. The
implementation accepts arbitrary user vectors, so the represented
access structure is the one induced over $F$, not necessarily the one
the caller intended over integers. Choose $p$ large enough to avoid
accidental modular dependencies. The constructor delegates to the span
program constructor, which rejects zero-width vectors. There is no
tamper correction; a bad share in a minimal qualified set can produce a
wrong secret.

## `massey`: Linear-Code Secret Sharing

Reference: `massey1993minimal`.

### Construction

Publish a generator matrix

$$
G \in F^{k \times (n+1)}.
$$

Column $0$ is the secret slot, and columns $1,\ldots,n$ are player
slots. To share $s$, choose a random row vector $m \in F^k$ subject to

$$
m G_0 = s,
$$

where $G_0$ is the secret column. Player $j$ receives

$$
c_j = m G_j.
$$

Massey's dual-code theorem characterizes the minimal qualified
coalitions as minimal dual codewords whose secret coordinate is
non-zero. The implementation uses the equivalent column-span test.

### Correctness

A coalition $C$ is qualified when

$$
G_0 \in \mathrm{span}\{G_j : j \in C\}.
$$

If

$$
G_0 = \sum_{j \in C} \alpha_j G_j,
$$

then

$$
s = mG_0
= m \sum_{j \in C} \alpha_j G_j
= \sum_{j \in C} \alpha_j c_j.
$$

### Perfect Privacy

If $C$ is unqualified, $G_0$ is not in the span of its player columns.
Thus there is a vector $z \in F^k$ with

$$
zG_j = 0 \quad \text{for all } j \in C
$$

and

$$
zG_0 \neq 0.
$$

Adding a scalar multiple of $z$ to the dealer's message vector changes
$mG_0$, and hence the secret, while preserving every value $mG_j$ seen
by $C$. This gives a bijection between consistent dealer randomness for
any two candidate secrets, so the coalition's view is independent of
the secret.

### Caveats

The mathematical scheme requires the secret column to be nonzero in
$F^k$. The constructor reduces every matrix entry modulo $p$ and then
checks that column zero is nonzero, so raw multiples of $p$ do not pass
as secret-column support. The constructor does not prove that the
matrix realizes an intended policy; qualification is exactly the
field-linear column-span relation after reduction modulo $p$. As in the
other linear schemes, shares are not authenticated: a tampered share can
make a qualified coalition recover the wrong value.

## `visual`: Naor-Shamir Visual Cryptography

Reference: `naor1994visual`.

### Construction

The implemented visual scheme is the canonical $(n, n)$ construction
for black-and-white images. Each secret pixel expands to

$$
m = 2^{n-1}
$$

subpixels per share. Let $C_0$ be the $n \times m$ basis matrix whose
columns are indexed by even-cardinality subsets of
$\{1,\ldots,n\}$, and let $C_1$ be the corresponding matrix for
odd-cardinality subsets. Entry $(i,\sigma)$ is black exactly when
$i \in \sigma$.

For a white pixel, the dealer chooses a uniform random column
permutation of $C_0$ and gives row $i$ to share image $i$. For a black
pixel, it does the same with $C_1$.

### Correctness

Stacking transparencies is bitwise OR. For a white pixel, the only
all-white stacked column is the column indexed by the empty subset, so
the stacked block has Hamming weight

$$
2^{n-1} - 1.
$$

For a black pixel, every odd subset is nonempty, so every stacked
column is black and the Hamming weight is

$$
2^{n-1}.
$$

The decoder reads those two possible block weights as white and black,
respectively.

### Perfect Privacy

Let $T$ be any set of $t < n$ shares. For any fixed $t$-bit row pattern
$r$, the number of even subsets of $\{1,\ldots,n\}$ whose projection
onto $T$ is $r$ equals the number of odd subsets with that same
projection. There is at least one player outside $T$, and toggling that
outside player's membership is a bijection that flips parity while
leaving the projection onto $T$ unchanged.

After the random column permutation, the restricted rows seen by $T$
therefore have exactly the same distribution for $C_0$ and $C_1$.
Thus any strict subset of the $n$ images has information-theoretic
privacy for every secret pixel.

### Caveats

This module implements $(n, n)$ visual cryptography only, not the full
general $(k, n)$ family. The pixel expansion is exponential in $n$.
It protects binary pixel values in the visual stacking model; it is not
a compact general-purpose byte secret-sharing format.

## `vss`: Rabin-Ben-Or Verifiable Secret Sharing

Reference: `rabin1989vss`.

### Construction

Choose a bivariate polynomial

$$
F(x,y) = \sum_{a=0}^{k-1} \sum_{b=0}^{k-1} c_{a,b} x^a y^b
$$

with

$$
F(0,0) = s.
$$

Player $i$ receives the two univariate slices

$$
g_i(y) = F(i,y)
$$

and

$$
h_i(x) = F(x,i).
$$

### Correctness

Pairwise consistency follows from

$$
g_i(j) = F(i,j) = h_j(i).
$$

For reconstruction, define

$$
\Phi(x) = F(x,0).
$$

This is a degree $< k$ polynomial, and player $i$ supplies
$\Phi(i) = g_i(0)$. Any $k$ consistent players interpolate $\Phi$ and
recover

$$
s = \Phi(0).
$$

### Perfect Privacy

Let $T$ be a corrupt coalition with $|T| = t < k$. To show that its
view is independent of the secret, fix any desired delta
$\Delta \in F$ and define

$$
D(x,y) =
\Delta
\cdot
\prod_{i \in T} \frac{x - i}{0 - i}
\cdot
\prod_{i \in T} \frac{y - i}{0 - i}.
$$

This polynomial has degree $t$ in each variable, so it fits within the
degree bound. It satisfies

$$
D(0,0) = \Delta
$$

and for every corrupt player $i \in T$,

$$
D(i,y) = 0
$$

and

$$
D(x,i) = 0.
$$

Adding $D$ changes the secret by $\Delta$ but leaves every corrupt
player's two slices unchanged. Therefore every corrupt view compatible
with one secret is compatible with every other secret in the same
number of ways.

### Verification and Caveats

The pairwise checks provide information-theoretic consistency, not a
standalone network protocol. Rabin-Ben-Or's active-security setting
requires an honest majority. In this module's threshold notation that
bound is

$$
2(k - 1) < n.
$$

The helper `is_honest_majority` exposes that predicate, but `deal` does
not enforce it because callers may use the consistency checker in a
larger protocol harness.

## `cgma_vss`: Computational VSS With Discrete-Log Commitments

Reference: `feldman1987practical`; computational VSS background:
`chor1985vss`.

### Construction

The module implements the standard Feldman-style computational VSS
template over a Schnorr group. The mathematical template requires a
prime $p$, a prime subgroup order $q$, and a generator $g$ of the
order-$q$ subgroup. `DlogGroup::new` checks those relations: it
Miller-Rabin tests $p$ and $q$, checks $q \mid p-1$, reduces and
rejects the identity generator, and verifies $g^q = 1 \pmod p$. Since
$q$ is prime and $g \ne 1$, that pins the order of $g$ to exactly $q$,
up to the probabilistic soundness of the primality test. Under valid
parameters, the dealer samples a Shamir polynomial over
$\mathbb{F}_q$:

$$
f(x) = a_0 + a_1 x + \cdots + a_{k-1}x^{k-1},
$$

with $a_0 = s$. The public commitments are

$$
c_i = g^{a_i} \pmod p
$$

for $0 \le i < k$. Player $j$ receives

$$
(j, f(j)).
$$

A player accepts its share when

$$
g^{f(j)} =
\prod_{i=0}^{k-1} c_i^{j^i}
\pmod p.
$$

### Correctness

For an honest dealer,

$$
\prod_{i=0}^{k-1} c_i^{j^i}
= \prod_{i=0}^{k-1} (g^{a_i})^{j^i}
= g^{\sum_{i=0}^{k-1} a_i j^i}
= g^{f(j)}.
$$

Thus every honest share verifies. Any $k$ verified shares reconstruct
$f(0)=s$ by ordinary Shamir interpolation over $\mathbb{F}_q$.

### Security Status

This module is not information-theoretically secure. The commitments,
including

$$
c_0 = g^s,
$$

are public. They hide their exponents only under the computational
hardness of discrete logarithms in the chosen group, and small secret
spaces can be searched directly.

For fixed valid prime-order parameters, the commitments bind
algebraically to one exponent polynomial modulo $q$: if two coefficient
vectors gave the same commitments, then $g^{a_i-a_i'} = 1$ for each
$i$, so $a_i = a_i' \pmod q$. Thus a verifying share is consistent
with the committed polynomial. This binding does not make the scheme
information-theoretically private, because the public commitments are
not perfectly hiding. The share values themselves must still be
delivered over private authenticated channels; this module verifies
shares but does not encrypt them or run the full interactive CGMA
protocol.

### Caveats

Do not use the bundled `small_test_group` for security. The constructor
validates supplied parameters but does not generate new groups or give a
formal primality certificate; for large inputs its Miller-Rabin test is
probabilistic. `verify_share` also rejects player labels that would
alias the secret slot modulo $q$ and rejects commitments outside the
order-$q$ subgroup. This scheme is useful when computational
assumptions and a private authenticated channel model are acceptable;
it is not a replacement for `vss` when information-theoretic secrecy or
an honest-majority protocol is required.

## `proactive`: Shamir Share Refresh

Reference: `herzberg1995proactive`.

### Construction

This module is a proactive refresh layer for Shamir shares, not a new
access structure. Suppose the current epoch's shares lie on

$$
Q(x)
$$

with $Q(0)=s$ and $\deg Q < k$. Each player samples a zero-constant
polynomial

$$
r_i(x) = a_{i,1}x + a_{i,2}x^2 + \cdots + a_{i,k-1}x^{k-1}
$$

and sends $r_i(x_j)$ to player $j$. Player $j$ updates

$$
y_j' = y_j + \sum_i r_i(x_j).
$$

Equivalently, the refreshed shares lie on

$$
Q'(x) = Q(x) + R(x),
$$

where

$$
R(x) = \sum_i r_i(x)
$$

and $R(0)=0$.

### Correctness

Because every contribution has zero constant term,

$$
Q'(0) = Q(0) + R(0) = s.
$$

The refreshed shares are therefore a new Shamir sharing of the same
secret at the same $x$ coordinates. The `recover_share` helper uses
Lagrange interpolation on any $k$ live shares to compute the missing
value at a lost coordinate $x_{\mathrm{lost}}$:

$$
y_{\mathrm{lost}} = Q(x_{\mathrm{lost}}).
$$

### Information-Theoretic Refresh Privacy

In the proactive model, old local state is securely erased between
epochs and the adversary corrupts fewer than $k$ players in any one
epoch. The aggregate refresh polynomial $R$ has independently uniform
nonconstant coefficients as long as at least one honest contribution is
fresh and uniform, with the other contributions fixed independently of
it. Adding $R$ to $Q$ makes the nonconstant coefficients of $Q'$ fresh
and uniform while preserving the constant term. Thus each epoch is
distributed as a fresh Shamir sharing of $s$.

An adversary that sees fewer than $k$ shares in any one epoch learns
nothing about $s$ in that epoch. With secure erasure between epochs,
mobile corruptions do not accumulate valid shares of one polynomial:
old and refreshed shares belong to different random polynomials with
the same constant term.

### Caveats

The implementation simulates the bare resharing step in one process.
It does not model private channels, authentication, complaints, secure
erasure, or the distributed scheduling assumptions of the
Herzberg-Jarecki-Krawczyk-Yung protocol. That protocol also verifies
refresh contributions before applying them. Without that verification,
a bad contributor can corrupt refreshed shares. The input must already
be a valid Shamir sharing of one degree $< k$ polynomial; `refresh`
checks label shape but does not prove consistency of the starting
shares. Pair refresh with VSS or commitments when parties may be
malicious. If an adversary ever obtains $k$ shares from the same epoch,
proactive refresh cannot save that already-exposed secret.

## `ida`: Rabin Information Dispersal Is Not Secret Sharing

Reference: `rabin1989ida`.

IDA is implemented in this crate because it is a Reed-Solomon relative
of the ramp schemes, but it is not a secret-sharing scheme.

### Construction and Correctness

Split a file into groups of $k$ field elements, treat each group as the
coefficient vector of a degree $< k$ polynomial, and distribute
evaluations of that polynomial. Any $k$ evaluations recover the
polynomial and therefore all $k$ original coefficients.

### Secrecy Status

There is no secrecy guarantee. A coalition with enough evaluations
recovers the data, and smaller coalitions still receive linear
information about the data coefficients. IDA is an erasure code for
availability and storage efficiency.

### Caveats

Use IDA for non-secret data dispersal, load balancing, or fault
tolerance. Do not use it to protect a secret unless the data has already
been encrypted or shared by a real secret-sharing scheme.

## `decode`: Berlekamp-Welch Robust Reconstruction Is Not a Scheme

Reference: `mceliece1981sharing`.

The `decode` module does not distribute secrets. It reconstructs a
Shamir/Reed-Solomon sharing in the presence of up to $t$ bad shares.

### Correctness

Given received points $(x_i,y_i)$, look for polynomials $Q$ and $E$
such that

$$
Q(x_i) = y_i E(x_i)
$$

for all supplied points, with

$$
\deg Q < k + t
$$

and

$$
\deg E \le t.
$$

If at most $t$ shares are erroneous and the true message polynomial is
$M$, then

$$
Q(x) = M(x)E(x)
$$

satisfies these equations when $E$ vanishes at the erroneous labels.
The decoder solves the resulting linear system and divides

$$
M(x) = Q(x) / E(x).
$$

The usual Reed-Solomon unique decoding bound is

$$
m - 2t \ge k,
$$

where $m$ is the number of supplied shares.

### Security Status

This layer adds robustness, not privacy. Secrecy remains exactly the
secrecy of the underlying sharing scheme. If the original shares were
Shamir shares, coalitions below threshold still have Shamir privacy; if
the original primitive was a ramp or IDA construction, Berlekamp-Welch
does not turn it into perfect secret sharing.

### Caveats

If more than $t$ shares are corrupted, decoding is outside the unique
decoding guarantee. It may fail, or it may return a wrong polynomial
when the supplied points have enough agreement with a competing
codeword. Robust decoding also does not authenticate the dealer or
prove that a sharing was generated honestly; use `vss` or a
protocol-level verification mechanism for that.


## Field-Arithmetic Optimisations

This section documents the algebra behind the two optimisation paths
the BigUint and field layers exploit. Both are textbook techniques
adapted to the project's conventions (no external dependencies, no
constant-time claims on the bigint backend, all operations matched
bit-for-bit between the Rust and C++ ports).

### Pseudo-Mersenne and Solinas Reduction

The standardised primes that ECC and authenticated-encryption papers
use are not arbitrary; they are chosen so that reduction modulo $p$
is far cheaper than the generic Montgomery reduction.

A *pseudo-Mersenne* prime has the form

$$
p = 2^k - c, \qquad 0 < c \ll 2^k.
$$

Examples: $2^{127} - 1$ (Mersenne, $c = 1$), $2^{255} - 19$
(Curve25519, $c = 19$), $2^{130} - 5$ (Poly1305).

A *Solinas* (or *generalised Mersenne*) prime is the same shape with
$c$ replaced by a short signed sum of powers of two:

$$
p = 2^k - \delta, \qquad \delta = \sum_i s_i \cdot 2^{e_i}, \quad s_i \in \{-1, +1\}, \quad e_i < k.
$$

Examples (FIPS 186-4 NIST primes):

* P-192: $p = 2^{192} - 2^{64} - 1$, so $\delta = 2^{64} + 1$.
* P-224: $p = 2^{224} - 2^{96} + 1$, so $\delta = 2^{96} - 1$.
* P-256: $p = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1$, so
  $\delta = 2^{224} - 2^{192} - 2^{96} + 1$.
* P-384: $p = 2^{384} - 2^{128} - 2^{96} + 2^{32} - 1$, so
  $\delta = 2^{128} + 2^{96} - 2^{32} + 1$.
* secp256k1: $p = 2^{256} - 2^{32} - 977$, so $\delta = 2^{32} + 977$.
* Curve448: $p = 2^{448} - 2^{224} - 1$, so $\delta = 2^{224} + 1$.

The fundamental identity in $\mathbb{Z}/p\mathbb{Z}$ is

$$
2^k \equiv \delta \pmod{p}.
$$

Given a product $t = a \cdot b$ with $0 \le a, b < p < 2^k$, we have
$0 \le t < 2^{2k}$. Splitting into low and high halves at bit $k$:

$$
t = \text{high} \cdot 2^k + \text{low}, \qquad 0 \le \text{low} < 2^k, \quad 0 \le \text{high} < 2^k.
$$

Substituting the identity yields

$$
t \equiv \text{low} + \text{high} \cdot \delta \pmod{p}.
$$

For pseudo-Mersenne $\delta$ with $\log_2 \delta \ll k$, the new value
fits in roughly $k + \log_2 \delta$ bits, so one or two folds of this
form drive $t$ below $2^{k+1}$, after which a single conditional
subtract pins it to $[0, p)$. For Solinas $\delta$ with terms
$s_i \cdot 2^{e_i}$, the fold becomes

$$
t \equiv \text{low} + \sum_i s_i \cdot \text{high} \cdot 2^{e_i} \pmod{p}.
$$

Each shift $\text{high} \cdot 2^{e_i}$ is a limb-level left shift —
no multiplication required when $|s_i| = 1$.

#### Convergence

Let $b(x)$ denote $\lceil \log_2 (x+1) \rceil$. After one fold step
on a value with $b(t) > k$,

$$
b(\text{result}) \le \max\left(b(\text{low}), b(\text{high}) + \max_i e_i + \lceil \log_2 |s_i \cdot \text{(number of terms)}|\rceil\right),
$$

so each fold strips at least $k - \max_i e_i$ bits from the magnitude
when $\delta > 0$ and the sum is taken with appropriate sign-tracking.
In the catalogue, the worst case is NIST P-256 ($\max e_i = 224$,
$k = 256$), which strips ~32 bits per fold and converges from a
$2k = 512$-bit product in roughly $\lceil 256 / 32 \rceil = 8$
iterations. The implementation hard-asserts a generous cap of 32
folds; reaching it indicates a corrupted parameter table rather than
a numerical issue.

#### The δ > 0 Invariant

The implementation accumulates positive and negative term
contributions into separate $\mathtt{BigUint}$ running sums and
returns $\text{pos} - \text{neg}$ at the end of each fold. This is
correct precisely when $\text{pos} \ge \text{neg}$ at every step.
Since

$$
\text{pos} - \text{neg} = \text{low} + \text{high} \cdot \delta
$$

and $\text{low}, \text{high} \ge 0$, a sufficient condition is
$\delta > 0$. Construction-time validation
(`validate_reduction_params`) checks this for every catalogue entry
by computing $\delta$ from its term decomposition and rejecting if
$\delta \le 0$ or if $\delta \ne 2^k - p$. The validation runs once
behind a `OnceLock`, so its cost is amortised over every subsequent
`PrimeField::mul`.

#### Why nist_p256 Routes to Generic

NIST P-256's polynomial has four terms with mixed signs and
$\max e_i = 224$ (close to $k = 256$), so each fold strips only ~32
bits — the algorithm needs ~8 iterations, each doing 4 BigUint
shifts and adds. Empirically that costs more than Montgomery's
4 mont-muls on 4 limbs. The catalogue still recognises P-256
(with the entry's `prefer_fast` flag set to `false`) so the
parametric reducer's correctness for that polynomial is exercised
by the per-prime fuzz harness, but production callers route to
Montgomery via the dispatch.

### Window-Method Modular Exponentiation

Modular exponentiation $\text{base}^e \bmod n$ is the inner loop of
verifiable-secret-sharing schemes that commit via a discrete-log
group (Feldman / CGMA-VSS). The textbook *square-and-multiply*
algorithm is the natural baseline:

> Walk the bits of $e$ MSB to LSB. Square the running result on
> every bit. When the bit is 1, multiply by the base.

For a uniformly random $n$-bit exponent this costs

$$
n \text{ squarings} + \tfrac{n}{2} \text{ multiplies} \approx 1.5 n \text{ Montgomery multiplications.}
$$

The *fixed-window* variant with window size $w$ improves the
multiply count. Precompute a table

$$
T[i] = \text{base}^i \pmod{n}, \qquad 0 \le i < 2^w,
$$

at a one-time cost of $2^w - 2$ multiplications (since $T[0] = 1$
and $T[1] = \text{base}$). Then walk the exponent in $w$-bit
windows, MSB first: square the running result $w$ times, look up
the next $w$-bit window of $e$ as an index $i$, and multiply by
$T[i]$. The total cost becomes

$$
n \text{ squarings} + \frac{n}{w} \text{ multiplies} + (2^w - 2) \text{ setup multiplies}.
$$

Setting $w = 4$ (the implementation choice) gives a 16-entry table
costing 14 setup multiplies and reduces the body cost from
$\tfrac{n}{2}$ to $\tfrac{n}{4}$ multiplies. For a 256-bit exponent
this saves $(128 - 64 - 14) = 50$ Montgomery multiplications
($\approx 13\%$ of the total $1.5n = 384$); for 2048-bit it saves
$(1024 - 512 - 14) = 498$ ($\approx 16\%$). The empirical win on
`cgma_vss_reconstruct` is 12 ms → 10.77 ms, $\approx 11\%$.

#### Skip-on-Zero and Side Channel

The implementation skips the multiply step entirely when a window
index is 0, recovering more time on exponents with many zero
windows. This and the data-dependent table indexing make the
operation **non-constant-time on the exponent**. The current callers
in this crate all use *public* exponents (the player abscissa $j$
in CGMA-VSS verification, treated as a small public integer), so the
leakage is benign. The docstrings on `MontgomeryCtx::pow` and
`pow_encoded` flag the surface and direct callers with secret
exponents (RSA, DH, signing) to a constant-time alternative — which
would have to read all $2^w$ table entries unconditionally and
multiply on every window using $T[0] = 1$ as a no-op for the zero
case.

#### Underflow Hazard at Short Exponents

A subtle hazard in the MSB-first scan: the natural index variable is
"position of the bit just below the most-recently-consumed window."
For an $n$-bit exponent with leading partial window of width
$\ell \in [1, w-1]$, the position after the partial window is
$n - 1 - \ell$, which can be 0 (when $n = \ell$) or — if computed as
$\text{top} - \ell$ on `usize` — wrap to `usize::MAX` when
$\text{top} < \ell$. The implementation drives the scan from a
monotonically-decreasing `remaining = n` counter that's checked in
the loop guard rather than from a `top - width` subtraction, so the
unsigned arithmetic cannot underflow even for $n \in \{1, 2, 3\}$.
Regression tests pin this for every exponent in $[0, 20]$ and for
the all-zero-windows case $2^{16}$.

## Threshold-Driven Algorithm Dispatch

Several primitives in this crate exhibit a *crossover regime*:
algorithm A is faster below some input-size threshold, algorithm B
above it, and the only honest way to pick the threshold is to
measure. Three current examples:

* **Karatsuba vs schoolbook multiplication** (`bigint::mul_ref`).
  Karatsuba's recursive split costs an asymptotic
  $O(n^{\log_2 3}) \approx O(n^{1.58})$ vs schoolbook's $O(n^2)$,
  but its constant factor is high. The crate dispatches to Karatsuba
  only when both operands have at least
  `KARATSUBA_THRESHOLD_LIMBS = 32` limbs and their length ratio is
  at most `KARATSUBA_MAX_IMBALANCE = 2`.

* **Window-method vs binary-scan exponentiation**
  (`MontgomeryCtx::pow`). The 4-bit window incurs $2^w - 2 = 14$
  setup multiplies before the main loop. Below break-even (~56 bits
  of exponent), the binary scan wins. The crate uses
  `POW_WINDOW_THRESHOLD_BITS = 64` with a small safety margin on the
  binary side.

* **CRT precomp vs per-fold extended-Euclidean**
  (`MignotteSequence::reconstruct`, `AsmuthBloomParams::reconstruct`).
  Pairwise inverses cached at construction trade $k - 1$
  `mod_inverse` calls per reconstruct for $O(k^2)$ `mod_mul` calls.
  Each `BigUint::mod_mul` rebuilds a `MontgomeryCtx`, so at small
  modulus sizes the setup outweighs the saving; at $\ge 128$-bit
  moduli the saving wins. The crate uses
  `CRT_PRECOMP_THRESHOLD_BITS = 128`.

The pattern they share — and the rule the implementation follows —
is the following:

1. **Thresholds must be measured, not guessed.** Pilot-bench is the
   ground truth in this repo; "I think algorithm B is faster" lost
   cleanly on the CRT precomp before measurement. Constants live as
   named items so the threshold can be retuned in one place when
   measurement contradicts intuition.

2. **Both branches must have regression coverage.** A future
   refactor that re-routes everything through one path should fail
   a test, not silently change performance. For the window method,
   `montgomery_pow_handles_short_exponents` exercises the binary
   path and `montgomery_pow_handles_zero_windows` exercises the
   window path; for the CRT precomp,
   `mignotte::tests::small_example_skips_precomp` and
   `large_example_uses_precomp` together pin both branches plus
   the dispatch decision.

3. **Dispatch decisions must not depend on secret inputs.** All
   three thresholds above key off the *size* of the operand, which
   is public (a modulus's bit length, a public abscissa's bit
   length). A "use binary scan if exponent is short" rule applied
   to a secret RSA decryption exponent would leak the bit-length
   of the secret; the side-channel notes on `MontgomeryCtx::pow`
   document the surface and direct secret-exponent callers
   elsewhere.

The threshold constants are deliberately conservative: a small
margin on the side that does *not* benefit from algorithm B's
specialised structure. This avoids regressions when measurement
noise crosses the line, at the cost of a few percent on inputs
near the boundary.

## References and Further Reading

The short reference keys above correspond to `bib/references.bib` when
that file contains the source. Extra entries here cover named
mathematical and implementation techniques that are used in the theory
but are not themselves secret-sharing papers.

* `shamir1979share`: Adi Shamir, "How to Share a Secret,"
  Communications of the ACM 22(11), 1979.
* `karnin1983secret`: Ehud D. Karnin, Jonathan W. Greene, and Martin
  E. Hellman, "On Secret Sharing Systems," IEEE Transactions on
  Information Theory 29(1), 1983.
* `blakley1979safeguarding`: George R. Blakley, "Safeguarding
  Cryptographic Keys," AFIPS Conference Proceedings 48, 1979.
* `blakley1984ramp`: George R. Blakley and Catherine Meadows,
  "Security of Ramp Schemes," CRYPTO 1984.
* `kothari1984generalized`: Suresh C. Kothari, "Generalized Linear
  Threshold Scheme," CRYPTO 1984.
* `mignotte1983secret`: Maurice Mignotte, "How to Share a Secret,"
  Workshop on Cryptography, 1983.
* `asmuth1983modular`: Charles Asmuth and John Bloom, "A Modular
  Approach to Key Safeguarding," IEEE Transactions on Information
  Theory 29(2), 1983.
* `mceliece1981sharing`: Robert J. McEliece and Dilip V. Sarwate, "On
  Sharing Secrets and Reed-Solomon Codes," Communications of the ACM
  24(9), 1981.
* `yamamoto1986secret`: Hirosuke Yamamoto, "Secret Sharing System
  Using $(k,L,n)$ Threshold Scheme," Electronics and Communications in
  Japan 69(9), 1986.
* `ito1989secret`: Mitsuru Ito, Akira Saito, and Takao Nishizeki,
  "Secret Sharing Scheme Realizing General Access Structure,"
  Electronics and Communications in Japan 72(9), 1989.
* `benaloh1990generalized`: Josh Benaloh and Jerry Leichter,
  "Generalized Secret Sharing and Monotone Functions," CRYPTO 1988.
* `karchmer1993span`: Mauricio Karchmer and Avi Wigderson, "On Span
  Programs," Structure in Complexity Theory, 1993.
* `vandijk1994linear`: Marten van Dijk, "A Linear Construction of
  Perfect Secret Sharing Schemes," EUROCRYPT 1994.
* `brickell1989ideal`: Ernest F. Brickell, "Some Ideal Secret Sharing
  Schemes," EUROCRYPT 1989.
* `massey1993minimal`: James L. Massey, "Minimal Codewords and Secret
  Sharing," 6th Joint Swedish-Russian Workshop on Information Theory,
  1993.
* `naor1994visual`: Moni Naor and Adi Shamir, "Visual Cryptography,"
  EUROCRYPT 1994.
* `rabin1989vss`: Tal Rabin and Michael Ben-Or, "Verifiable Secret
  Sharing and Multiparty Protocols with Honest Majority," STOC 1989.
* `chor1985vss`: Benny Chor, Shafi Goldwasser, Silvio Micali, and
  Baruch Awerbuch, "Verifiable Secret Sharing and Achieving
  Simultaneity in the Presence of Faults," FOCS 1985.
* `feldman1987practical`: Paul Feldman, "A Practical Scheme for
  Non-Interactive Verifiable Secret Sharing," FOCS 1987.
* `herzberg1995proactive`: Amir Herzberg, Stanislaw Jarecki, Hugo
  Krawczyk, and Moti Yung, "Proactive Secret Sharing Or: How to Cope
  With Perpetual Leakage," CRYPTO 1995.
* `rabin1989ida`: Michael O. Rabin, "Efficient Dispersal of
  Information for Security, Load Balancing, and Fault Tolerance,"
  Journal of the ACM 36(2), 1989.
* `reed1960polynomial`: Irving S. Reed and Gustave Solomon,
  "Polynomial Codes over Certain Finite Fields," Journal of the
  Society for Industrial and Applied Mathematics 8(2), 1960.
* `berlekamp1968algebraic`: Elwyn R. Berlekamp, Algebraic Coding
  Theory, McGraw-Hill, 1968.
* `roth2006coding`: Ron M. Roth, Introduction to Coding Theory,
  Cambridge University Press, 2006.
* `menezes1996handbook`: Alfred J. Menezes, Paul C. van Oorschot, and
  Scott A. Vanstone, Handbook of Applied Cryptography, CRC Press, 1996.
* `gathen2013modern`: Joachim von zur Gathen and Jurgen Gerhard,
  Modern Computer Algebra, Cambridge University Press, 2013.
* `miller1976riemann`: Gary L. Miller, "Riemann's Hypothesis and Tests
  for Primality," Journal of Computer and System Sciences 13(3), 1976.
* `rabin1980probabilistic`: Michael O. Rabin, "Probabilistic Algorithm
  for Testing Primality," Journal of Number Theory 12(1), 1980.
* `schnorr1991efficient`: Claus-Peter Schnorr, "Efficient Signature
  Generation by Smart Cards," Journal of Cryptology 4(3), 1991.
* `montgomery1985modular`: Peter L. Montgomery, "Modular
  Multiplication Without Trial Division," Mathematics of Computation
  44(170), 1985.
* `solinas1999generalized`: Jerome A. Solinas, "Generalized Mersenne
  Numbers," Technical Report CORR 99-39, University of Waterloo, 1999.
* `nist2013fips1864`: NIST FIPS 186-4, Digital Signature Standard,
  2013, for the named NIST prime shapes used in the code.
* `karatsuba1963multiplication`: Anatoly Karatsuba and Yuri Ofman,
  "Multiplication of Multidigit Numbers on Automata," Soviet Physics
  Doklady 7, 1963.
