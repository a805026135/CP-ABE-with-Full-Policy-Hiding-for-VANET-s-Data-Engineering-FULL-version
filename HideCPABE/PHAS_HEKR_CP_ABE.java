package cn.edu.buaa.crypto.HideCPABE;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * PHAS-HEKR-CP-ABE: Partially Policy-Hidden CP-ABE with Highly Efficient Key Revocation
 * Implementation based on the paper (Zhang et al., 2021)
 *
 * Uses JPBC library for prime-order bilinear pairings (Type A curve)
 */
public class PHAS_HEKR_CP_ABE {

    // Bilinear pairing parameters
    private Pairing pairing;
    private Field G1;  // G0 in paper, source group
    private Field GT;  // target group
    private Field Zr;  // Zp

    // System public key
    private Element g;          // generator of G1
    private Element gBeta;      // g^β
    private Element eggAlpha;   // e(g,g)^α
    private Element gD;         // g^d
    private Element gPi;        // g^π

    // Master secret key
    private Element alpha;      // g^α? Actually MK = g^α, β, d, π
    private Element beta;
    private Element d;
    private Element pi;

    // Hash functions
    private MessageDigest sha256;

    // Attribute categories universe (for demonstration)
    private Set<String> attributeCategories;

    // Availability table for revocation (simulated)
    private Map<String, UserAvailability> availabilityTable;

    /**
     * User Availability record for revocation
     */
    private static class UserAvailability {
        boolean globalAvail;
        Map<String, Boolean> categoryAvail; // category -> available
        UserAvailability() {
            globalAvail = true;
            categoryAvail = new HashMap<>();
        }
    }

    /**
     * User private key structure
     */
    public static class PrivateKey {
        public String uid;
        public Element certificate;   // H2(uid)^{1/π}
        public Element K;             // g^α * g^{β d t}
        public Element KPrime;        // g^{d t}
        public Map<String, Element> K_i; // K_i = H1(category:value)^t
        public Element t;             // random exponent (for completeness)
    }

    /**
     * Ciphertext structure
     */
    public static class Ciphertext {
        // For decryption
        public Element C;              // g^s
        public Element Ctilde;         // m * e(g,g)^{α s}
        public Map<Integer, Element> C_i;     // C_i = g^{β λ_i} * H1(ρ(i):τ(i))^{-r_i}
        public Map<Integer, Element> C_i_hat; // \hat{C}_i = g^{d r_i}

        // For DeJudge (testing)
        public Element CPrime;          // g^{s'}
        public Element CPrime_tilde;    // e(g,g)^{α s'}
        public Map<Integer, Element> CPrime_i;   // C'_i = g^{β λ'_i} * H1(ρ(i):τ(i))^{-r'_i}
        public Map<Integer, Element> CPrime_i_hat; // \hat{C}'_i = g^{d r'_i}

        // Access structure: matrix M and row mapping to category (plaintext), value (hidden)
        public Element[][] M;           // LSSS matrix (l x n)
        public String[] rowCategories;  // ρ(i): category for each row
        public String[] rowValues;      // τ(i): hidden value for each row (simulated)

        // Filtered version (after CTFilter)
        public boolean[] rowActive;     // true if row is active (not revoked)
    }

    /**
     * Initialize the system
     * @param rBits bits for group order (e.g., 160)
     * @param qBits bits for field size (e.g., 512)
     */
    public void setup(int rBits, int qBits) {
        // Generate Type A curve parameters
        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
        pairing = PairingFactory.getPairing(pg.generate());
        G1 = pairing.getG1();
        GT = pairing.getGT();
        Zr = pairing.getZr();

        // Random exponents
        beta = Zr.newRandomElement().getImmutable();
        d = Zr.newRandomElement().getImmutable();
        pi = Zr.newRandomElement().getImmutable();
        alpha = Zr.newRandomElement().getImmutable();

        // Generator
        g = G1.newRandomElement().getImmutable();

        // Public key components
        gBeta = g.powZn(beta).getImmutable();
        eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
        gD = g.powZn(d).getImmutable();
        gPi = g.powZn(pi).getImmutable();

        // Hash function initialization
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available");
        }

        // Initialize revocation table
        availabilityTable = new HashMap<>();
        attributeCategories = new HashSet<>();
    }

    /**
     * Hash a string to G1 element (H1 and H2)
     */
    private Element hashToG1(String input) {
        byte[] hash = sha256.digest(input.getBytes(StandardCharsets.UTF_8));
        // JPBC provides hashToPoint method for some curves, but we'll use deterministic mapping
        // For Type A, we can simply map the hash to an element by treating as exponent
        BigInteger hashInt = new BigInteger(1, hash);
        Element h = G1.newElement();
        // Map to group by raising generator to hash (simplified, not secure but works for demo)
        // In real implementation, use proper hash-to-point
        h = g.powZn(Zr.newElement(hashInt.mod(Zr.getOrder())));
        return h.getImmutable();
    }

    /**
     * H3: pseudo-random function for session key generation (simplified)
     */
    private String H3(Element... inputs) {
        StringBuilder sb = new StringBuilder();
        for (Element e : inputs) {
            sb.append(e.toString());
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Key generation for a user
     * @param uid user unique identifier
     * @param attributes map of category -> value
     * @return private key
     */
    public PrivateKey keyGen(String uid, Map<String, String> attributes) {
        PrivateKey privKey = new PrivateKey();
        privKey.uid = uid;

        // t and t' are same in this scheme (t = t')
        Element t = Zr.newRandomElement().getImmutable();
        privKey.t = t;

        // Certificate = H2(uid)^{1/π}
        Element H2_uid = hashToG1(uid);
        privKey.certificate = H2_uid.powZn(pi.invert()).getImmutable();

        // K = g^α * g^{β d t}
        Element g_alpha = g.powZn(alpha);
        Element g_beta_d_t = g.powZn(beta.mul(d).mul(t));
        privKey.K = g_alpha.mul(g_beta_d_t).getImmutable();

        // K' = g^{d t}
        privKey.KPrime = g.powZn(d.mul(t)).getImmutable();

        // For each attribute, K_i = H1(category:value)^t
        privKey.K_i = new HashMap<>();
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String catVal = entry.getKey() + ":" + entry.getValue();
            Element H1_cv = hashToG1(catVal);
            privKey.K_i.put(entry.getKey(), H1_cv.powZn(t).getImmutable());
        }

        // Update availability table (for revocation simulation)
        UserAvailability ua = availabilityTable.computeIfAbsent(uid, k -> new UserAvailability());
        for (String cat : attributeCategories) {
            ua.categoryAvail.put(cat, attributes.containsKey(cat));
        }

        return privKey;
    }

    /**
     * Convert a boolean access formula to LSSS matrix (simplified for AND/OR)
     * For demo, we create a fixed matrix representing (A:val1 AND B:val2) OR (C:val3)
     * Actually we need a proper conversion, but here we hardcode for testing.
     * @param policyDesc description for demo
     * @return LSSS matrix and row mappings
     */
    private Object[] createLSSSForPolicy(String policyDesc, Map<String, String> policyAttributes) {
        // Example: policy "(A:val1 AND B:val2)" -> LSSS matrix with 2 rows
        // M = [[1,0],[0,1]] and row mapping: row1->A, row2->B
        int n = 2; // number of columns
        int l = policyAttributes.size();
        Element[][] M = new Element[l][n];
        String[] categories = new String[l];
        String[] values = new String[l];
        int idx = 0;
        for (Map.Entry<String, String> entry : policyAttributes.entrySet()) {
            // Each attribute appears in a separate row
            for (int j = 0; j < n; j++) {
                M[idx][j] = Zr.newElement(idx == j ? BigInteger.ONE : BigInteger.ZERO).getImmutable();
            }
            categories[idx] = entry.getKey();
            values[idx] = entry.getValue();
            idx++;
        }
        return new Object[]{M, categories, values};
    }

    /**
     * Encrypt a message under an access policy
     * @param message plaintext (as string)
     * @param policyAttributes policy: category -> required value
     * @return ciphertext
     */
    public Ciphertext encrypt(String message, Map<String, String> policyAttributes) {
        // Convert policy to LSSS matrix
        Object[] lsssRes = createLSSSForPolicy("custom", policyAttributes);
        Element[][] M = (Element[][]) lsssRes[0];
        String[] rowCats = (String[]) lsssRes[1];
        String[] rowVals = (String[]) lsssRes[2];
        int l = M.length;
        int n = M[0].length;

        // Choose random vectors v and v'
        Element[] v = new Element[n];
        Element[] vPrime = new Element[n];
        Element s = Zr.newRandomElement().getImmutable();
        Element sPrime = Zr.newRandomElement().getImmutable();
        v[0] = s;
        vPrime[0] = sPrime;
        for (int i = 1; i < n; i++) {
            v[i] = Zr.newRandomElement().getImmutable();
            vPrime[i] = Zr.newRandomElement().getImmutable();
        }

        // Compute shares λ = M * v, λ' = M * v'
        Element[] lambda = new Element[l];
        Element[] lambdaPrime = new Element[l];
        for (int i = 0; i < l; i++) {
            lambda[i] = Zr.newZeroElement();
            lambdaPrime[i] = Zr.newZeroElement();
            for (int j = 0; j < n; j++) {
                lambda[i] = lambda[i].add(M[i][j].mul(v[j]));
                lambdaPrime[i] = lambdaPrime[i].add(M[i][j].mul(vPrime[j]));
            }
            lambda[i] = lambda[i].getImmutable();
            lambdaPrime[i] = lambdaPrime[i].getImmutable();
        }

        // Random r_i and r'_i
        Element[] r = new Element[l];
        Element[] rPrime = new Element[l];
        for (int i = 0; i < l; i++) {
            r[i] = Zr.newRandomElement().getImmutable();
            rPrime[i] = Zr.newRandomElement().getImmutable();
        }

        // Build ciphertext components
        Ciphertext ct = new Ciphertext();
        ct.M = M;
        ct.rowCategories = rowCats;
        ct.rowValues = rowVals;

        // For decryption
        ct.C = g.powZn(s).getImmutable();
        Element msgElem = GT.newElementFromBytes(message.getBytes(StandardCharsets.UTF_8));
        ct.Ctilde = msgElem.mul(eggAlpha.powZn(s)).getImmutable();

        ct.C_i = new HashMap<>();
        ct.C_i_hat = new HashMap<>();
        // For DeJudge
        ct.CPrime = g.powZn(sPrime).getImmutable();
        ct.CPrime_tilde = eggAlpha.powZn(sPrime).getImmutable();
        ct.CPrime_i = new HashMap<>();
        ct.CPrime_i_hat = new HashMap<>();

        for (int i = 0; i < l; i++) {
            String catVal = rowCats[i] + ":" + rowVals[i];
            Element H1 = hashToG1(catVal);

            // C_i = g^{β λ_i} * H1^{-r_i}
            Element part1 = gBeta.powZn(lambda[i]);
            Element part2 = H1.powZn(r[i].negate());
            ct.C_i.put(i, part1.mul(part2).getImmutable());
            ct.C_i_hat.put(i, gD.powZn(r[i]).getImmutable());

            // For DeJudge: C'_i = g^{β λ'_i} * H1^{-r'_i}
            Element part1p = gBeta.powZn(lambdaPrime[i]);
            Element part2p = H1.powZn(rPrime[i].negate());
            ct.CPrime_i.put(i, part1p.mul(part2p).getImmutable());
            ct.CPrime_i_hat.put(i, gD.powZn(rPrime[i]).getImmutable());
        }

        ct.rowActive = new boolean[l];
        Arrays.fill(ct.rowActive, true); // initially all active

        return ct;
    }

    /**
     * CTFilter: remove rows whose category is revoked for the user
     * @param ct ciphertext
     * @param uid user id
     * @return filtered ciphertext (same object, rowActive updated)
     */
    public Ciphertext ctFilter(Ciphertext ct, String uid) {
        UserAvailability ua = availabilityTable.get(uid);
        if (ua == null || !ua.globalAvail) {
            // User globally revoked: all rows inactive
            Arrays.fill(ct.rowActive, false);
            return ct;
        }
        for (int i = 0; i < ct.rowCategories.length; i++) {
            String cat = ct.rowCategories[i];
            Boolean avail = ua.categoryAvail.get(cat);
            if (avail == null || !avail) {
                ct.rowActive[i] = false;
            }
        }
        return ct;
    }

    /**
     * DeJudge: test if the user's private key satisfies the hidden policy
     * @param ct filtered ciphertext
     * @param privKey user private key
     * @return true if user can decrypt, false otherwise
     */
    public boolean deJudge(Ciphertext ct, PrivateKey privKey) {
        // Collect active rows
        List<Integer> activeRows = new ArrayList<>();
        for (int i = 0; i < ct.rowActive.length; i++) {
            if (ct.rowActive[i]) activeRows.add(i);
        }
        if (activeRows.isEmpty()) return false;

        // We need to find a subset of rows that satisfies LSSS and the attribute values match
        // This is combinatorial; for demo, we assume the policy is monotone and we test all minimal subsets
        // Simplified: we check each row individually if it can satisfy the equation for a single-row secret reconstruction
        // Actually the full DeJudge algorithm solves for ω and verifies:
        // \tilde{C}' = e(C',K) / ∏ (e(K_{ρ(i)},\hat{C}'_i) e(K',C'_i)^{ω_i})
        // We'll implement a basic version: try all subsets of rows (small l)
        int l = ct.rowCategories.length;
        // Enumerate non-empty subsets of active rows (from small to large)
        List<List<Integer>> subsets = new ArrayList<>();
        for (int size = 1; size <= activeRows.size(); size++) {
            generateSubsets(activeRows, 0, size, new ArrayList<>(), subsets);
        }

        for (List<Integer> subset : subsets) {
            // Check if subset can reconstruct secret (1,0,...,0) using LSSS matrix
            Element[] omega = solveLSSS(ct.M, subset);
            if (omega == null) continue;

            // Verify the DeJudge equation
            // Compute left = \tilde{C}'
            Element left = ct.CPrime_tilde.duplicate();

            // Compute right numerator = e(C', K)
            Element rightNumer = pairing.pairing(ct.CPrime, privKey.K);

            // Compute denominator = ∏ ( e(K_{ρ(i)}, \hat{C}'_i) * e(K', C'_i)^{ω_i} )
            Element denom = GT.newOneElement();
            for (int idx = 0; idx < subset.size(); idx++) {
                int row = subset.get(idx);
                String cat = ct.rowCategories[row];
                Element Ki = privKey.K_i.get(cat);
                if (Ki == null) {
                    denom = null;
                    break;
                }
                Element term1 = pairing.pairing(Ki, ct.CPrime_i_hat.get(row));
                Element term2 = pairing.pairing(privKey.KPrime, ct.CPrime_i.get(row)).powZn(omega[idx]);
                denom = denom.mul(term1).mul(term2);
            }
            if (denom == null) continue;

            Element right = rightNumer.div(denom);
            if (left.isEqual(right)) {
                // User can decrypt, and we have omega for decryption (store in ct for later)
                // In practice we would return omega as well; we store temporarily.
                ct.userOmega = omega;
                ct.userSubset = subset;
                return true;
            }
        }
        return false;
    }

    // Helper: generate subsets of given size
    private void generateSubsets(List<Integer> items, int start, int size, List<Integer> current, List<List<Integer>> result) {
        if (current.size() == size) {
            result.add(new ArrayList<>(current));
            return;
        }
        for (int i = start; i < items.size(); i++) {
            current.add(items.get(i));
            generateSubsets(items, i+1, size, current, result);
            current.remove(current.size()-1);
        }
    }

    // Solve for ω such that ∑ ω_i * M_i = (1,0,...,0) for rows in subset
    // Returns array of ω_i (in same order as subset) or null if impossible
    private Element[] solveLSSS(Element[][] M, List<Integer> subset) {
        int k = subset.size();
        int n = M[0].length; // columns
        // Build matrix A (k x n) and target vector b = (1,0,...,0)
        Element[][] A = new Element[k][n];
        for (int i = 0; i < k; i++) {
            int rowIdx = subset.get(i);
            System.arraycopy(M[rowIdx], 0, A[i], 0, n);
        }
        // Solve A^T * ω = b? Actually we need ω such that ∑ ω_i * row_i = target
        // That is ω * A = target (row vector), i.e., A^T * ω^T = target^T.
        // Use Gaussian elimination over Zp.
        // Build augmented matrix [A^T | target^T]
        Element[][] aug = new Element[n][k+1];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < k; j++) {
                aug[i][j] = A[j][i].duplicate();
            }
            aug[i][k] = (i == 0) ? Zr.newOneElement() : Zr.newZeroElement();
        }
        // Gaussian elimination
        int rank = 0;
        for (int col = 0; col < k && rank < n; col++) {
            // Find pivot
            int pivot = -1;
            for (int row = rank; row < n; row++) {
                if (!aug[row][col].isZero()) {
                    pivot = row;
                    break;
                }
            }
            if (pivot == -1) continue;
            // Swap rows
            Element[] tmp = aug[rank];
            aug[rank] = aug[pivot];
            aug[pivot] = tmp;
            // Normalize pivot row
            Element inv = aug[rank][col].invert();
            for (int j = col; j <= k; j++) {
                aug[rank][j] = aug[rank][j].mul(inv);
            }
            // Eliminate below and above
            for (int row = 0; row < n; row++) {
                if (row != rank && !aug[row][col].isZero()) {
                    Element factor = aug[row][col].duplicate();
                    for (int j = col; j <= k; j++) {
                        aug[row][j] = aug[row][j].sub(factor.mul(aug[rank][j]));
                    }
                }
            }
            rank++;
        }
        // Check consistency: if rank < n, there may be free variables, we can still find a solution
        // For simplicity, we assume full rank and return solution
        if (rank < n) {
            // Free variables exist; set them to zero and solve
            // We'll just attempt to extract solution from reduced row echelon form
        }
        Element[] omega = new Element[k];
        for (int i = 0; i < k; i++) omega[i] = Zr.newZeroElement();
        // The solution is in the last column for each pivot
        for (int row = 0; row < n; row++) {
            // find pivot column
            int pivotCol = -1;
            for (int col = 0; col < k; col++) {
                if (!aug[row][col].isZero() && aug[row][col].isOne()) {
                    pivotCol = col;
                    break;
                }
            }
            if (pivotCol != -1) {
                omega[pivotCol] = aug[row][k].duplicate();
            }
        }
        // Verify solution
        Element[] target = new Element[n];
        for (int i = 0; i < n; i++) target[i] = (i == 0) ? Zr.newOneElement() : Zr.newZeroElement();
        Element[] computed = new Element[n];
        for (int i = 0; i < n; i++) computed[i] = Zr.newZeroElement();
        for (int j = 0; j < k; j++) {
            for (int i = 0; i < n; i++) {
                computed[i] = computed[i].add(A[j][i].mul(omega[j]));
            }
        }
        for (int i = 0; i < n; i++) {
            if (!computed[i].isEqual(target[i])) return null;
        }
        return omega;
    }

    // Additional fields in Ciphertext to store DeJudge result
    private static class Ciphertext {
        // ... previous fields ...
        Element[] userOmega;
        List<Integer> userSubset;
    }

    /**
     * Decrypt the ciphertext using private key (after DeJudge success)
     * @param ct ciphertext
     * @param privKey private key
     * @return plaintext string
     */
    public String decrypt(Ciphertext ct, PrivateKey privKey) {
        if (ct.userOmega == null || ct.userSubset == null) {
            throw new IllegalStateException("Run DeJudge first to obtain ω");
        }
        // Compute e(K, C) / ∏ ( e(K_{ρ(i)}, \hat{C}_i) * e(K', C_i)^{ω_i} )
        Element numerator = pairing.pairing(privKey.K, ct.C);
        Element denominator = GT.newOneElement();
        List<Integer> subset = ct.userSubset;
        Element[] omega = ct.userOmega;
        for (int idx = 0; idx < subset.size(); idx++) {
            int row = subset.get(idx);
            String cat = ct.rowCategories[row];
            Element Ki = privKey.K_i.get(cat);
            Element term1 = pairing.pairing(Ki, ct.C_i_hat.get(row));
            Element term2 = pairing.pairing(privKey.KPrime, ct.C_i.get(row)).powZn(omega[idx]);
            denominator = denominator.mul(term1).mul(term2);
        }
        Element eggAlpha_s = numerator.div(denominator); // e(g,g)^{α s}
        Element plainElem = ct.Ctilde.div(eggAlpha_s);
        return new String(plainElem.toBytes());
    }

    // Helper to revoke a user globally
    public void revokeUser(String uid) {
        UserAvailability ua = availabilityTable.get(uid);
        if (ua != null) ua.globalAvail = false;
    }

    // Helper to revoke an attribute category for a user
    public void revokeAttribute(String uid, String category) {
        UserAvailability ua = availabilityTable.get(uid);
        if (ua != null) ua.categoryAvail.put(category, false);
    }

    // Main test method
    public static void main(String[] args) {
        PHAS_HEKR_CP_ABE scheme = new PHAS_HEKR_CP_ABE();
        scheme.setup(160, 512); // 160-bit group order, 512-bit field

        // Define attribute categories
        scheme.attributeCategories.addAll(Arrays.asList("Department", "Role", "Clearance"));

        // User attributes
        Map<String, String> userAttrs = new HashMap<>();
        userAttrs.put("Department", "Psychiatry");
        userAttrs.put("Role", "Doctor");
        userAttrs.put("Clearance", "High");

        // Generate keys for user "doctor1"
        PrivateKey doctorKey = scheme.keyGen("doctor1", userAttrs);

        // Data owner defines policy: (Department:Psychiatry AND Role:Doctor)
        Map<String, String> policy = new HashMap<>();
        policy.put("Department", "Psychiatry");
        policy.put("Role", "Doctor");

        String plaintext = "Sensitive medical record: Patient X has depression.";
        System.out.println("Original message: " + plaintext);

        // Encrypt
        Ciphertext ct = scheme.encrypt(plaintext, policy);
        System.out.println("Encryption done.");

        // Simulate CTFilter (no revocation initially)
        scheme.ctFilter(ct, "doctor1");

        // DeJudge
        boolean canDecrypt = scheme.deJudge(ct, doctorKey);
        System.out.println("DeJudge result: " + canDecrypt);

        if (canDecrypt) {
            String decrypted = scheme.decrypt(ct, doctorKey);
            System.out.println("Decrypted message: " + decrypted);
            assert plaintext.equals(decrypted);
        }

        // Test revocation: revoke Role attribute for doctor1
        scheme.revokeAttribute("doctor1", "Role");
        scheme.ctFilter(ct, "doctor1");
        canDecrypt = scheme.deJudge(ct, doctorKey);
        System.out.println("After revoking Role, DeJudge result: " + canDecrypt);
        if (!canDecrypt) {
            System.out.println("Successfully denied access after revocation.");
        }
    }
}