// File: src/main/java/com/pmcpabe/PMCPABE.java
package cn.edu.buaa.crypto.HideCPABE;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class PMCPABE {
    private Pairing pairing;
    private Field<Element> G, GT;
    private BigInteger N, p1, p2, p3, p4;
    private Element g, g2, g3, g4;  // generators of subgroups
    private Element e_gg_alpha;      // e(g,g)^alpha
    private Map<String, AAInfo> aaMap;  // attribute name -> AA
    private Map<String, Element> aaPublicKeys; // attribute name -> Z_j

    // System parameters
    private Element g_a;   // g^a
    private Element alpha; // master secret part
    private Element a;     // exponent
    private Element g_alpha; // g^alpha
    private Map<String, Element> userSK_HMA; // GID -> SK_{GID,HMA}
    private Map<String, BigInteger> userT;   // GID -> t

    public static class AAInfo {
        Element A_j;  // in G_{p1}
        Element D_j;  // in G_{p4}
        Element Z_j;  // public key = A_j * D_j
    }

    public PMCPABE() {
        initPairing();
        setup();
    }

    private void initPairing() {
        // Generate four primes of 64 bits each (for demonstration)
        p1 = BigInteger.probablePrime(64, new Random());
        p2 = BigInteger.probablePrime(64, new Random());
        p3 = BigInteger.probablePrime(64, new Random());
        p4 = BigInteger.probablePrime(64, new Random());
        N = p1.multiply(p2).multiply(p3).multiply(p4);
        System.out.println("N = " + N);
        PropertiesParameters params = new PropertiesParameters();
        params.put("type", "a1");
        params.put("n", N.toString());
        params.put("q", N.toString());
        TypeA1CurveGenerator curveGen = new TypeA1CurveGenerator(N);
        PairingFactory.getInstance().setUsePBCWhenPossible(false);
        pairing = PairingFactory.getPairing(curveGen.generate());
        G = pairing.getG1();
        GT = pairing.getGT();
    }

    private void setup() {
        // SystemSetup by HMA
        Element h = G.newRandomElement(); // random generator of full group
        // Compute subgroup generators
        BigInteger orderG1 = p2.multiply(p3).multiply(p4);
        BigInteger orderG2 = p1.multiply(p3).multiply(p4);
        BigInteger orderG3 = p1.multiply(p2).multiply(p4);
        BigInteger orderG4 = p1.multiply(p2).multiply(p3);
        g = h.pow(orderG1);  // order = p1
        g2 = h.pow(orderG2); // order = p2
        g3 = h.pow(orderG3); // order = p3
        g4 = h.pow(orderG4); // order = p4

        a = G.newRandomElement().getImmutable();
        alpha = G.newRandomElement().getImmutable();
        Element g_a_tmp = g.duplicate().powZn(a);
        g_a = g_a_tmp.duplicate().getImmutable();
        e_gg_alpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        aaMap = new HashMap<>();
        aaPublicKeys = new HashMap<>();
        userSK_HMA = new HashMap<>();
        userT = new HashMap<>();
    }

    public void aaSetup(String attrName) {
        // AASetup: each AA for a specific attribute name
        AAInfo aa = new AAInfo();
        aa.A_j = g.duplicate().powZn(G.newRandomElement()).getImmutable(); // random in G_{p1}
        aa.D_j = g4.duplicate().powZn(G.newRandomElement()).getImmutable(); // random in G_{p4}
        aa.Z_j = aa.A_j.duplicate().mul(aa.D_j).getImmutable();
        aaMap.put(attrName, aa);
        aaPublicKeys.put(attrName, aa.Z_j);
    }

    public Map<String, Element> userRegistration(String GID) {
        // UserRegistration: HMA generates partial key for user
        if (userSK_HMA.containsKey(GID)) return null;
        BigInteger tBig = new BigInteger(N.bitLength(), new Random()).mod(N);
        Element t = G.newElement().set(tBig).getImmutable();
        Element C = g3.duplicate().powZn(G.newRandomElement()).getImmutable();
        Element Cp = g3.duplicate().powZn(G.newRandomElement()).getImmutable();
        Element K = g_a.duplicate().mul(g.duplicate().powZn(a).powZn(t)).mul(C).getImmutable();
        Element Kp = g.duplicate().powZn(t).mul(Cp).getImmutable();
        Map<String, Element> partialKey = new HashMap<>();
        partialKey.put("K", K);
        partialKey.put("Kp", Kp);
        userSK_HMA.put(GID, K);
        userT.put(GID, tBig);
        return partialKey;
    }

    public Map<String, Element> attributeKeyGen(String GID, String attrName, String attrValue,
                                                Map<String, Element> userPartialKey) {
        // AttributeKeyGen by AA for a specific attribute name and value
        AAInfo aa = aaMap.get(attrName);
        if (aa == null) throw new RuntimeException("AA not found for attribute: " + attrName);
        BigInteger t = userT.get(GID);
        Element tElem = G.newElement().set(t).getImmutable();
        // Convert attrValue to element in Z_N
        BigInteger valBig = hashToZr(attrValue);
        Element s_i = G.newElement().set(valBig).getImmutable();
        Element g_si = g.duplicate().powZn(s_i).getImmutable();
        Element A_j = aa.A_j;
        Element base = g_si.duplicate().mul(A_j).getImmutable();
        Element K_i = base.powZn(tElem).getImmutable();
        // Add randomness from G_{p2}
        Element B_i = g2.duplicate().powZn(G.newRandomElement()).getImmutable();
        K_i = K_i.mul(B_i).getImmutable();
        Map<String, Element> keyFragment = new HashMap<>();
        keyFragment.put(attrName, K_i);
        return keyFragment;
    }

    public Map<String, Element> transformKeyGen(Map<String, Element> fullSK, BigInteger z) {
        // TransformKeyGen: user creates transform key by exponentiating with 1/z
        Map<String, Element> tk = new HashMap<>();
        for (Map.Entry<String, Element> entry : fullSK.entrySet()) {
            Element val = entry.getValue();
            Element invZ = G.newElement().set(z.modInverse(N)).getImmutable();
            Element transformed = val.duplicate().powZn(invZ).getImmutable();
            tk.put(entry.getKey(), transformed);
        }
        return tk;
    }

    public Map<String, Object> encrypt(String message, AccessPolicy policy) throws Exception {
        // Encrypt: DS encrypts data under access policy
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message.getBytes(StandardCharsets.UTF_8));
        Element VK = G.newElement().setFromHash(hash, 0, hash.length).getImmutable();

        int n = policy.getMatrix().length; // number of rows
        int cols = policy.getMatrix()[0].length; // number of columns (including secret)
        BigInteger[] v = new BigInteger[cols];
        BigInteger s = new BigInteger(N.bitLength(), new Random()).mod(N);
        v[0] = s;
        for (int i = 1; i < cols; i++) {
            v[i] = new BigInteger(N.bitLength(), new Random()).mod(N);
        }
        Element C_tilde = GT.newElement().set(e_gg_alpha).powZn(G.newElement().set(s)).getImmutable();
        Element D = g4.duplicate().powZn(G.newRandomElement()).getImmutable();
        Element C = g.duplicate().powZn(G.newElement().set(s)).mul(D).getImmutable();

        List<Element> C_x_list = new ArrayList<>();
        for (int x = 0; x < n; x++) {
            // compute A_x * v
            BigInteger dot = BigInteger.ZERO;
            for (int j = 0; j < cols; j++) {
                dot = dot.add(BigInteger.valueOf(policy.getMatrix()[x][j]).multiply(v[j])).mod(N);
            }
            Element A_x_v = G.newElement().set(dot).getImmutable();
            Element term1 = g.duplicate().powZn(a).powZn(A_x_v).getImmutable();
            String attrName = policy.getRowToAttr()[x];
            String attrValue = policy.getRowToValue()[x];
            Element Z_j = aaPublicKeys.get(attrName);
            BigInteger valBig = hashToZr(attrValue);
            Element g_t = g.duplicate().powZn(G.newElement().set(valBig)).getImmutable();
            Element term2 = g_t.duplicate().mul(Z_j).getImmutable();
            term2 = term2.powZn(G.newElement().set(s.negate().mod(N))).getImmutable();
            Element D_x = g4.duplicate().powZn(G.newRandomElement()).getImmutable();
            Element C_x = term1.mul(term2).mul(D_x).getImmutable();
            C_x_list.add(C_x);
        }
        Map<String, Object> ciphertext = new HashMap<>();
        ciphertext.put("VK", VK);
        ciphertext.put("A", policy);
        ciphertext.put("C_tilde", C_tilde);
        ciphertext.put("C", C);
        ciphertext.put("C_x", C_x_list);
        return ciphertext;
    }

    public Element outsourcingDecrypt(Map<String, Object> ct, Map<String, Element> tk,
                                      AccessPolicy policy, BigInteger z) throws Exception {
        // ES: partially decrypts using transform key
        List<Element> C_x = (List<Element>) ct.get("C_x");
        Element C = (Element) ct.get("C");
        Element Kp = tk.get("Kp");
        Element K = tk.get("K");

        // Find minimal authorized set X
        Set<Integer> X_set = findMinimalAuthorizedSet(policy, getUserAttributesFromTK(tk));
        if (X_set == null) return null; // not authorized

        List<Integer> X = new ArrayList<>(X_set);
        // Reconstruct coefficients omega_x
        BigInteger[] omega = computeReconstructionCoefficients(policy, X);
        Element prod1 = GT.newOneElement();
        for (int idx = 0; idx < X.size(); idx++) {
            int x = X.get(idx);
            Element C_x_elem = C_x.get(x);
            Element omega_elem = G.newElement().set(omega[idx]).getImmutable();
            Element term = pairing.pairing(C_x_elem, Kp);
            prod1 = prod1.mul(term.powZn(omega_elem));
        }
        Element prod2 = GT.newOneElement();
        Element K_inv = K.duplicate().powZn(G.newElement().set(z.modInverse(N).negate().mod(N))).getImmutable();
        Element base2 = C.duplicate();
        for (int idx = 0; idx < X.size(); idx++) {
            int x = X.get(idx);
            String attrName = policy.getRowToAttr()[x];
            Element K_i = tk.get(attrName);
            Element omega_elem = G.newElement().set(omega[idx]).getImmutable();
            Element factor = K_i.duplicate().powZn(omega_elem);
            base2 = base2.mul(factor);
        }
        prod2 = pairing.pairing(base2, K_inv);
        Element CT_prime = prod1.mul(prod2);
        return CT_prime;
    }

    public String userDecrypt(Map<String, Object> ct, Element CT_prime, BigInteger z, Element VK) throws Exception {
        Element C_tilde = (Element) ct.get("C_tilde");
        Element result = C_tilde.duplicate().mul(CT_prime);
        result = result.powZn(G.newElement().set(z.modInverse(N)));
        String message = new String(result.toBytes()); // simplistic, but for demo
        // Verify
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message.getBytes(StandardCharsets.UTF_8));
        Element computedVK = G.newElement().setFromHash(hash, 0, hash.length);
        if (computedVK.isEqual(VK)) return message;
        else throw new Exception("Verification failed");
    }

    // Helper methods
    private BigInteger hashToZr(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(1, hash).mod(N);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private Set<Integer> findMinimalAuthorizedSet(AccessPolicy policy, Set<String> userAttrs) {
        // Simplified: returns first set of rows where attributes match
        Set<Integer> authorized = new HashSet<>();
        for (int i = 0; i < policy.getMatrix().length; i++) {
            if (userAttrs.contains(policy.getRowToAttr()[i])) {
                authorized.add(i);
            }
        }
        // Check if reconstruction possible (simplified: enough rows)
        if (authorized.size() >= policy.getMatrix()[0].length) return authorized;
        return null;
    }

    private BigInteger[] computeReconstructionCoefficients(AccessPolicy policy, List<Integer> X) {
        // Simplified: assume matrix is full rank, return unit vector for first column
        BigInteger[] omega = new BigInteger[X.size()];
        omega[0] = BigInteger.ONE;
        for (int i = 1; i < omega.length; i++) omega[i] = BigInteger.ZERO;
        return omega;
    }

    private Set<String> getUserAttributesFromTK(Map<String, Element> tk) {
        Set<String> attrs = new HashSet<>();
        for (String key : tk.keySet()) {
            if (!key.equals("K") && !key.equals("Kp")) attrs.add(key);
        }
        return attrs;
    }

    // AccessPolicy class (simplified for demo)
    public static class AccessPolicy {
        private int[][] matrix;
        private String[] rowToAttr;
        private String[] rowToValue;

        public AccessPolicy(int[][] matrix, String[] rowToAttr, String[] rowToValue) {
            this.matrix = matrix;
            this.rowToAttr = rowToAttr;
            this.rowToValue = rowToValue;
        }
        public int[][] getMatrix() { return matrix; }
        public String[] getRowToAttr() { return rowToAttr; }
        public String[] getRowToValue() { return rowToValue; }
    }
}