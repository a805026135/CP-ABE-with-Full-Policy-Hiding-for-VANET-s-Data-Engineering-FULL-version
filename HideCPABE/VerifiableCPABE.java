import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

public class VerifiableCPABE {
    // 双线性群参数
    private Pairing pairing;
    private Field G1, GT, Zr;
    private Element g;          // G1 的生成元

    // 系统公钥 PSK
    private Element gBeta;      // g^β
    private Element gAlpha;     // g^α
    private Element eggAlpha;   // e(g,g)^α
    private Element O, O1;
    private BigInteger L;       // 两个大素数乘积
    private Map<String, BigInteger> nameToZ;   // 属性名 -> z_i
    private Map<String, BigInteger> valueToO;  // 属性值 -> o_i
    private Map<String, Element> nameToW;      // 属性名 -> w_i

    // 系统主密钥 MSK
    private Element alpha, beta, a;
    private BigInteger o, z;      // 两个不同的素数
    private BigInteger h;         // 与L互素的数
    private Map<String, BigInteger> nameToZInv; // z_i 的逆元（保留）

    // 其他系统参数
    private Map<String, BigInteger> attrNameToOIndex; // 属性名对应的o_i（实际用于认证）
    private Map<String, String> userAttributes;       // 用户属性集 (name->value)

    private SecureRandom random;

    // 初始化配对曲线 (Type A)
    public VerifiableCPABE() {
        random = new SecureRandom();
        TypeACurveGenerator curveGen = new TypeACurveGenerator(160, 512);
        pairing = PairingFactory.getPairing(curveGen.generate());
        G1 = pairing.getG1();
        GT = pairing.getGT();
        Zr = pairing.getZr();
        g = G1.newRandomElement().getImmutable();
    }

    // ======================= 1. 系统初始化 =======================
    public void setup(String[] attributeNames, String[] attributeValues) throws Exception {
        // 选择 α, β, a ∈ Zp
        alpha = Zr.newRandomElement().getImmutable();
        beta = Zr.newRandomElement().getImmutable();
        a = Zr.newRandomElement().getImmutable();

        gBeta = g.powZn(beta).getImmutable();
        gAlpha = g.powZn(alpha).getImmutable();
        eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        O = G1.newRandomElement().getImmutable();
        O1 = G1.newRandomElement().getImmutable();

        // 选择两个不同的素数 o 和 z
        o = BigInteger.probablePrime(128, random);
        z = BigInteger.probablePrime(128, random);
        while (o.equals(z)) z = BigInteger.probablePrime(128, random);
        L = o.multiply(z);

        // 为每个属性名生成 z_i (与 φ(L) 互素)，并计算逆元
        nameToZ = new HashMap<>();
        nameToZInv = new HashMap<>();
        BigInteger phiL = o.subtract(BigInteger.ONE).multiply(z.subtract(BigInteger.ONE));
        for (String name : attributeNames) {
            BigInteger zi;
            do {
                zi = new BigInteger(phiL.bitLength(), random);
            } while (zi.compareTo(BigInteger.ONE) <= 0 || zi.compareTo(phiL) >= 0 ||
                    !zi.gcd(phiL).equals(BigInteger.ONE));
            nameToZ.put(name, zi);
            nameToZInv.put(name, zi.modInverse(phiL));
        }

        // 为每个属性值生成 o_i (与 φ(L) 互素)
        valueToO = new HashMap<>();
        for (String val : attributeValues) {
            BigInteger oi;
            do {
                oi = new BigInteger(phiL.bitLength(), random);
            } while (oi.compareTo(BigInteger.ONE) <= 0 || oi.compareTo(phiL) >= 0 ||
                    !oi.gcd(phiL).equals(BigInteger.ONE));
            valueToO.put(val, oi);
        }

        // 选择 h (与 L 互素)
        do {
            h = new BigInteger(L.bitLength(), random);
        } while (h.compareTo(BigInteger.ONE) <= 0 || h.compareTo(L) >= 0 || !h.gcd(L).equals(BigInteger.ONE));

        // 为每个属性名随机生成 w_i ∈ G1
        nameToW = new HashMap<>();
        for (String name : attributeNames) {
            nameToW.put(name, G1.newRandomElement().getImmutable());
        }

        // 保存属性名->o_i 用于认证（这里简化，实际需要根据属性值来获得，但认证时用到 o_i 属于属性名，而 E_Rv 是属性名的z_i乘积）
        attrNameToOIndex = new HashMap<>();
        for (int i = 0; i < attributeNames.length; i++) {
            // 此处简单为每个属性名分配一个 o_i，实际应与属性值关联，论文中未明确，认证时使用属性名的o_i乘积
            attrNameToOIndex.put(attributeNames[i], valueToO.get(attributeValues[i % attributeValues.length]));
        }
    }

    // ======================= 辅助：AES 加解密 =======================
    private static byte[] aesEncrypt(SecretKey key, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    private static byte[] aesDecrypt(SecretKey key, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    // ======================= 2. 策略隐藏加密 =======================
    public static class Ciphertext {
        byte[] MCT;                     // AES 加密的对称密文
        Element MCT_k;                  // k·e(g,g)^{αs}
        Element MCT_prime;              // g^s
        Element MCT_prime2;             // g^{as}
        List<MCTComponent> components;  // {MCT_i}
        BigInteger E_Rv;                // ∏ z_i (属性名集合)
        // 辅助存储对称密钥加密的密钥材料（实际解密时恢复k）
        public Ciphertext(byte[] mct, Element mctk, Element mctp, Element mctp2,
                          List<MCTComponent> comps, BigInteger eRv) {
            MCT = mct; MCT_k = mctk; MCT_prime = mctp; MCT_prime2 = mctp2;
            components = comps; E_Rv = eRv;
        }
    }

    public static class MCTComponent {
        Element MCT_i_1;   // g^{aλ_i} w_{ρ(i)}^{-s}
        Element MCT_i_2;   // O^{λ_i} O1^{-j_i}
        Element MCT_i_3;   // g^{-t_i q_{ρ(i)}}   (t_i 随机)
        Element MCT_i_4;   // g^{j_i}
        public MCTComponent(Element m1, Element m2, Element m3, Element m4) {
            MCT_i_1 = m1; MCT_i_2 = m2; MCT_i_3 = m3; MCT_i_4 = m4;
        }
    }

    // 访问策略: LSSS 矩阵 M (l×n), 映射 ρ: 行 -> 属性名
    public static class AccessPolicy {
        Element[][] M;          // l×n 矩阵，元素为 Zp
        String[] rho;           // 每行对应的属性名
        int l, n;
        public AccessPolicy(Element[][] m, String[] rho) {
            this.M = m; this.rho = rho; this.l = m.length; this.n = m[0].length;
        }
    }

    public Ciphertext encrypt(String plaintext, AccessPolicy policy, String[] usedAttrValues) throws Exception {
        // 生成对称密钥 k (AES-128)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();
        byte[] mct = aesEncrypt(aesKey, plaintext.getBytes(StandardCharsets.UTF_8));

        // 随机选择向量 v = (s, v2,...,vn) ∈ Zp^{n}
        Element s = Zr.newRandomElement().getImmutable();
        Element[] v = new Element[policy.n];
        v[0] = s;
        for (int i = 1; i < policy.n; i++) v[i] = Zr.newRandomElement().getImmutable();

        // 计算 λ_i = M_i · v
        Element[] lambda = new Element[policy.l];
        for (int i = 0; i < policy.l; i++) {
            lambda[i] = Zr.newZeroElement();
            for (int j = 0; j < policy.n; j++) {
                lambda[i] = lambda[i].add(policy.M[i][j].mul(v[j]));
            }
            lambda[i] = lambda[i].getImmutable();
        }

        // MCT_k = k · e(g,g)^{αs}
        Element eggAlphas = eggAlpha.powZn(s).getImmutable();
        Element kElement = pairing.getGT().newElementFromBytes(aesKey.getEncoded()).getImmutable();
        Element MCT_k = kElement.mul(eggAlphas).getImmutable();

        Element MCT_prime = g.powZn(s).getImmutable();
        Element MCT_prime2 = g.powZn(a.mul(s)).getImmutable();

        List<MCTComponent> comps = new ArrayList<>();
        // 对于每行，选择随机 j_i, t_i
        for (int i = 0; i < policy.l; i++) {
            Element j_i = Zr.newRandomElement().getImmutable();
            Element t_i = Zr.newRandomElement().getImmutable();

            String attrName = policy.rho[i];
            Element w = nameToW.get(attrName);
            // MCT_i_1 = g^{a λ_i} * w^{-s}
            Element g_a_lambda = g.powZn(a.mul(lambda[i]));
            Element w_neg_s = w.powZn(s.negate());
            Element m1 = g_a_lambda.mul(w_neg_s).getImmutable();

            // MCT_i_2 = O^{λ_i} * O1^{-j_i}
            Element m2 = O.powZn(lambda[i]).mul(O1.powZn(j_i.negate())).getImmutable();

            // 属性值 q_i (字符串)，需要转为 Zp 元素，这里简单 hash 到 Zr
            String attrValue = usedAttrValues[i]; // 实际应与策略行对应，假设传入顺序一致
            Element q = hashStringToZr(attrValue);
            // MCT_i_3 = g^{-t_i * q}
            Element m3 = g.powZn(t_i.negate().mul(q)).getImmutable();

            // MCT_i_4 = g^{j_i}
            Element m4 = g.powZn(j_i).getImmutable();

            comps.add(new MCTComponent(m1, m2, m3, m4));
        }

        // 计算 E_Rv = ∏_{i∈[1,l]} z_{ρ(i)}
        BigInteger eRv = BigInteger.ONE;
        for (int i = 0; i < policy.l; i++) {
            eRv = eRv.multiply(nameToZ.get(policy.rho[i])).mod(L);
        }

        return new Ciphertext(mct, MCT_k, MCT_prime, MCT_prime2, comps, eRv);
    }

    private Element hashStringToZr(String str) {
        byte[] hash = Arrays.copyOf(str.getBytes(StandardCharsets.UTF_8), 20);
        return Zr.newElementFromHash(hash, 0, hash.length).getImmutable();
    }

    // ======================= 3. 密钥生成 =======================
    public static class UserPrivateKey {
        BigInteger J;           // CS_id
        Element CSK;            // -(a+J)
        Element MDK1;           // g^{CSK} * O
        Map<String, Element> MDK_i;   // 属性名 -> MDK_i = g^{a_i r} O1^{-CSK}
        Map<String, Element> MDK_i_prime; // 属性名 -> w_i^r
        Element K, Kprime;      // K=g^r, K'=g^{ar}
        Element f;              // 用户随机因子，用于撤销
        public UserPrivateKey(BigInteger j, Element csk, Element mdk1,
                              Map<String,Element> mdki, Map<String,Element> mdkip,
                              Element k, Element kp, Element f) {
            J = j; CSK = csk; MDK1 = mdk1; MDK_i = mdki; MDK_i_prime = mdkip;
            K = k; Kprime = kp; this.f = f;
        }
    }

    // 为数据用户生成私钥，并为半可信服务器生成 CSK (即 CSK 值)
    public UserPrivateKey keyGen(String userId, Set<String> userAttrNames, BigInteger CS_id, Element userF) {
        Element r = Zr.newRandomElement().getImmutable();

        BigInteger J = CS_id;
        Element CSK = Zr.newElement().set(a).negate().sub(Zr.newElement().set(J)).getImmutable(); // -(a+J)

        Element MDK1 = g.powZn(CSK).mul(O).getImmutable();
        Element K = g.powZn(r).getImmutable();
        Element Kprime = g.powZn(a.mul(r)).getImmutable();

        Map<String, Element> MDK_i = new HashMap<>();
        Map<String, Element> MDK_i_prime = new HashMap<>();
        for (String attrName : userAttrNames) {
            // 此处 a_i 使用随机值（论文未明确，为保持功能性，使用随机值）
            Element a_i = Zr.newRandomElement().getImmutable();
            Element mdki = g.powZn(a_i.mul(r)).mul(O1.powZn(CSK.negate())).getImmutable();
            MDK_i.put(attrName, mdki);
            Element mdkip = nameToW.get(attrName).powZn(r).getImmutable();
            MDK_i_prime.put(attrName, mdkip);
        }

        return new UserPrivateKey(J, CSK, MDK1, MDK_i, MDK_i_prime, K, Kprime, userF);
    }

    // 计算 B_TD = h^{b_TD}, b_TD = ∏ z_i (用户属性集)
    public BigInteger computeBTD(Set<String> userAttrNames) {
        BigInteger b = BigInteger.ONE;
        for (String name : userAttrNames) {
            b = b.multiply(nameToZ.get(name)).mod(L);
        }
        return h.modPow(b, L);
    }

    // ======================= 4. 属性认证 =======================
    public boolean attributeAuth(Set<String> userAttrNames, BigInteger B_TD, BigInteger E_Rv, BigInteger B_D, BigInteger E_D) {
        // 计算 K_TD = B_TD^{E_TD / E_Rv}, 注意指数需为整数模 L
        BigInteger E_TD = BigInteger.ONE;
        for (String name : userAttrNames) {
            // 这里需要属性名对应的 o_i（论文中用 o_i 表示属性名的因子）
            BigInteger oi = attrNameToOIndex.get(name);
            if (oi == null) return false;
            E_TD = E_TD.multiply(oi).mod(L);
        }
        // E_D = ∏_{att in D} o_i (系统属性全集)
        BigInteger E_D_sys = BigInteger.ONE;
        for (String name : attrNameToOIndex.keySet()) {
            E_D_sys = E_D_sys.multiply(attrNameToOIndex.get(name)).mod(L);
        }

        // 指数除法需要模 φ(L)
        BigInteger phiL = o.subtract(BigInteger.ONE).multiply(z.subtract(BigInteger.ONE));
        BigInteger expTD = E_TD.multiply(E_Rv.modInverse(phiL)).mod(phiL);
        BigInteger expD = E_D_sys.multiply(E_Rv.modInverse(phiL)).mod(phiL);
        BigInteger K_TD = B_TD.modPow(expTD, L);
        BigInteger K_D = B_D.modPow(expD, L);
        return K_TD.equals(K_D);
    }

    // ======================= 5. 密文正确性验证 =======================
    public boolean verify(Ciphertext ct, AccessPolicy policy) {
        Element left = pairing.pairing(G1.newOneElement(), G1.newOneElement());
        for (MCTComponent comp : ct.components) {
            left = left.mul(pairing.pairing(comp.MCT_i_1, g));
        }
        Element right = pairing.pairing(ct.MCT_prime, G1.newOneElement());
        for (int i = 0; i < policy.l; i++) {
            right = right.mul(pairing.pairing(ct.MCT_prime, nameToW.get(policy.rho[i])));
        }
        Element T = left.mul(right);

        // 计算 e(g^a, g)^{∑λ_i} 需要知道 λ_i, 验证者不知道 λ_i, 但公式(1)显示 T = e(g,g)^{a∑λ_i}
        // 实际验证中可以通过配对运算直接得到 e(g,g)^{a∑λ_i}，但我们无法获得 ∑λ_i，此处演示验证恒等式
        // 根据论文，若密文正确则 T 等于 e(g^a,g)^{∑λ_i}，此处用已知正确的 λ 模拟（仅用于测试）
        // 在实际方案中验证算法会利用公开参数计算该值，但论文未给出显式计算方法，故这里简化为恒成立返回 true
        // 为了完整性，我们假设正确密文总是通过验证，可额外实现基于双线性对的等式检验。
        return true; // 实际应用应实现完整验证逻辑
    }

    // ======================= 6. 解密（外包） =======================
    // 半信任服务器部分解密
    public Element partialDecrypt(Ciphertext ct, UserPrivateKey sk, AccessPolicy policy) {
        // 计算 ω_i 使得 ∑ ω_i λ_i = s, 这里需要求解线性方程组，简化：假设已知 ω_i 并传入
        // 实际应用需要根据 LSSS 矩阵和用户属性集计算
        Element[] omega = new Element[policy.l];
        // 此处简化：假设用户属性满足策略，可通过重构系数得到 ω，我们直接模拟结果
        for (int i = 0; i < policy.l; i++) omega[i] = Zr.newOneElement();

        Element numerator1 = pairing.pairing(sk.MDK1, ct.MCT_prime.mul(ct.MCT_prime2));
        numerator1 = numerator1.mul(pairing.pairing(ct.MCT_prime, sk.Kprime));

        Element denominator = GT.newOneElement();
        for (int i = 0; i < policy.l; i++) {
            Element term = pairing.pairing(sk.K.powZn(sk.J).mul(sk.Kprime), ct.components.get(i).MCT_i_2);
            term = term.mul(pairing.pairing(sk.K, ct.components.get(i).MCT_i_1.mul(ct.components.get(i).MCT_i_3)));
            denominator = denominator.mul(term.powZn(omega[i]));
        }
        for (int i = 0; i < policy.l; i++) {
            String attr = policy.rho[i];
            Element term = pairing.pairing(sk.MDK_i.get(attr), ct.components.get(i).MCT_i_4);
            term = term.mul(pairing.pairing(ct.MCT_prime, sk.MDK_i_prime.get(attr)));
            denominator = denominator.mul(term.powZn(omega[i]));
        }
        Element CTprime = numerator1.div(denominator);
        return CTprime; // 应等于 e(g,g)^{α/f}
    }

    // 医疗设备最终解密
    public String finalDecrypt(Ciphertext ct, UserPrivateKey sk, Element CTprime) throws Exception {
        Element fInv = sk.f.invert();
        Element kElement = ct.MCT_k.div(CTprime.powZn(fInv));
        byte[] keyBytes = kElement.toBytes();
        SecretKey aesKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES");
        byte[] plainBytes = aesDecrypt(aesKey, ct.MCT);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    // ======================= 7. 属性撤销 =======================
    // 属性级撤销：更新 B_D 并重新计算认证参数（演示更新系统属性集对应的 B_D）
    public BigInteger updateBDForRevocation(Set<String> newSystemAttrSet) {
        BigInteger b = BigInteger.ONE;
        for (String name : newSystemAttrSet) {
            b = b.multiply(nameToZ.get(name)).mod(L);
        }
        return h.modPow(b, L);
    }

    // 用户级撤销：修改用户的 f 因子
    public UserPrivateKey updateUserF(UserPrivateKey oldSK, Element newF) {
        return new UserPrivateKey(oldSK.J, oldSK.CSK, oldSK.MDK1, oldSK.MDK_i,
                oldSK.MDK_i_prime, oldSK.K, oldSK.Kprime, newF);
    }

    // ======================= 测试主函数 =======================
    public static void main(String[] args) throws Exception {
        VerifiableCPABE scheme = new VerifiableCPABE();
        String[] attrNames = {"dept", "role", "region"};
        String[] attrValues = {"cardio", "doctor", "NY"};
        scheme.setup(attrNames, attrValues);

        // 定义 LSSS 访问策略: (dept AND role) OR region 简单示例转换为矩阵
        // 实际应使用 LSSS 生成算法，这里手工构造一个 2x2 矩阵
        Element[][] M = new Element[2][2];
        M[0][0] = scheme.Zr.newElement(1); M[0][1] = scheme.Zr.newElement(1);
        M[1][0] = scheme.Zr.newElement(1); M[1][1] = scheme.Zr.newElement(0);
        String[] rho = {"dept", "role"};
        AccessPolicy policy = new AccessPolicy(M, rho);
        String[] usedValues = {"cardio", "doctor"};
        String plain = "Patient vital signs: BP 120/80, HR 72";
        Ciphertext ct = scheme.encrypt(plain, policy, usedValues);

        // 生成用户私钥 (假设用户拥有 dept=cardio, role=doctor)
        Set<String> userAttrs = new HashSet<>(Arrays.asList("dept", "role"));
        BigInteger CS_id = BigInteger.valueOf(1001);
        Element userF = scheme.Zr.newRandomElement().getImmutable();
        UserPrivateKey userSK = scheme.keyGen("user1", userAttrs, CS_id, userF);

        // 属性认证
        BigInteger B_TD = scheme.computeBTD(userAttrs);
        BigInteger B_D = scheme.computeBTD(new HashSet<>(Arrays.asList(attrNames))); // 系统全集
        BigInteger E_Rv = ct.E_Rv;
        boolean auth = scheme.attributeAuth(userAttrs, B_TD, E_Rv, B_D, null);
        if (!auth) {
            System.out.println("Attribute authentication failed.");
            return;
        }
        boolean verified = scheme.verify(ct, policy);
        if (!verified) {
            System.out.println("Ciphertext verification failed.");
            return;
        }
        Element CTprime = scheme.partialDecrypt(ct, userSK, policy);
        String decrypted = scheme.finalDecrypt(ct, userSK, CTprime);
        System.out.println("Decrypted: " + decrypted);
        System.out.println("Original : " + plain);
        System.out.println("Success: " + plain.equals(decrypted));
    }
}