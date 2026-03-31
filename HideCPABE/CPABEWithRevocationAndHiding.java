package cn.edu.buaa.crypto.HideCPABE;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class CPABEWithRevocationAndHiding {

    private Pairing pairing;
    private Field G1, GT, Zr;
    private Element g, alpha, beta, g_alpha, egg_beta;
    private MessageDigest sha256;

    // 用户属性表 TB: 用户ID -> (属性名 -> 是否拥有)
    private Map<String, Map<String, Boolean>> userAttributeTable = new HashMap<>();

    public CPABEWithRevocationAndHiding() throws NoSuchAlgorithmException {
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing("a.properties"); // 需提供Type A曲线参数文件
        G1 = pairing.getG1();
        GT = pairing.getGT();
        Zr = pairing.getZr();
        g = G1.newRandomElement().getImmutable();
        alpha = Zr.newRandomElement().getImmutable();
        beta = Zr.newRandomElement().getImmutable();
        g_alpha = g.powZn(alpha).getImmutable();
        egg_beta = pairing.pairing(g, g).powZn(beta).getImmutable();
        sha256 = MessageDigest.getInstance("SHA-256");
    }

    // 哈希到Zr (H2, H3)
    private BigInteger hashToZr(String input) {
        byte[] hash = sha256.digest(input.getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, hash).mod(Zr.getOrder());
    }

    // 哈希到G1 (H1)
    private Element hashToG1(String input) {
        BigInteger h = hashToZr(input);
        return g.powZn(Zr.newElement(h)).getImmutable();
    }

    // 隐藏属性值 (H3)
    private String hideAttribute(String attr) {
        return hashToZr(attr).toString();
    }

    // ==================== 密钥生成 ====================
    public PrivateKey keyGen(String userId, Set<String> attrs) {
        Element t = Zr.newRandomElement();
        Element K = g.powZn(beta).mul(g_alpha.powZn(t)).getImmutable();
        Element Kp = g.powZn(t).getImmutable();
        Map<String, Element> Kc = new HashMap<>();
        for (String attr : attrs) {
            String hidden = hideAttribute(attr);
            Element H1 = hashToG1(hidden);
            Kc.put(attr, H1.powZn(t).getImmutable());
        }
        // 记录到用户属性表
        userAttributeTable.putIfAbsent(userId, new HashMap<>());
        for (String attr : attrs) {
            userAttributeTable.get(userId).put(attr, true);
        }
        return new PrivateKey(userId, K, Kp, Kc);
    }

    // ==================== 加密 ====================
    // M: n x l 矩阵, rho: 行号(1-index) -> 属性名
    public Ciphertext encrypt(String message, Element[][] M, Map<Integer, String> rho) {
        int n = M.length, l = M[0].length;
        // 随机向量 (s, v2, ..., vl)
        Element[] v = new Element[l];
        v[0] = Zr.newRandomElement(); // s
        for (int i = 1; i < l; i++) v[i] = Zr.newRandomElement();
        // 计算秘密份额 lambda_i
        Element[] lambda = new Element[n];
        for (int i = 0; i < n; i++) {
            lambda[i] = Zr.newZeroElement();
            for (int j = 0; j < l; j++) {
                lambda[i].add(M[i][j].duplicate().mul(v[j]));
            }
            lambda[i] = lambda[i].getImmutable();
        }
        // 随机数 r_i
        Element[] r = new Element[n];
        for (int i = 0; i < n; i++) r[i] = Zr.newRandomElement();

        Element C = g.powZn(v[0]).getImmutable();
        Element egg_s_beta = egg_beta.powZn(v[0]);
        // 消息转成Zr元素（简化）
        BigInteger msgInt = new BigInteger(message.getBytes(StandardCharsets.UTF_8));
        Element mElement = Zr.newElement(msgInt).getImmutable();
        Element C_tilde = mElement.duplicate().mul(egg_s_beta).getImmutable();

        List<CipherComponent> comps = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String attr = rho.get(i+1);
            String hidden = hideAttribute(attr);
            Element H1 = hashToG1(hidden);
            Element Ci = g_alpha.powZn(lambda[i]).mul(H1.powZn(r[i]).invert()).getImmutable();
            Element Cip = g.powZn(r[i]).getImmutable();
            comps.add(new CipherComponent(Ci, Cip, attr));
        }
        return new Ciphertext(comps, C, C_tilde, M, rho);
    }

    // ==================== 属性撤销 (Algorithm 1) ====================
    public RevokedCiphertext attributeRevoke(Ciphertext ct, String userId) {
        Map<String, Boolean> userRow = userAttributeTable.getOrDefault(userId, new HashMap<>());
        List<CipherComponent> newComps = new ArrayList<>();
        List<Element[]> newRows = new ArrayList<>();
        Map<Integer, String> newRho = new HashMap<>();

        int n = ct.components.size();
        for (int i = 0; i < n; i++) {
            CipherComponent comp = ct.components.get(i);
            String attr = comp.attr;
            // 如果用户拥有该属性，则保留；否则撤销（删除行）
            if (userRow.getOrDefault(attr, false)) {
                newComps.add(comp);
                newRows.add(ct.M[i]);
                newRho.put(newComps.size(), attr); // 新行号从1开始
            }
        }
        // 构建新矩阵
        int nf = newComps.size();
        Element[][] newM = new Element[nf][ct.M[0].length];
        for (int i = 0; i < nf; i++) {
            newM[i] = newRows.get(i);
        }
        return new RevokedCiphertext(newComps, ct.C, ct.C_tilde, newM, newRho);
    }

    // ==================== 策略隐藏 (构建HT) ====================
    // 使用哈希表HT存储 (索引 -> 行信息列表)
    public HiddenCiphertext policyStructureHiding(RevokedCiphertext revCt, String userId, String timestamp) {
        Map<Integer, List<RowInfo>> HT = new HashMap<>();
        int nf = revCt.components.size();
        for (int i = 0; i < nf; i++) {
            String attr = revCt.rho.get(i+1);
            // H2(rho_f(i), ID, t)
            String hashInput = attr + userId + timestamp;
            BigInteger hin = hashToZr(hashInput);
            int index = hin.mod(BigInteger.valueOf(1024)).intValue(); // 哈希表大小可调
            RowInfo info = new RowInfo(i+1, revCt.M[i]);
            HT.computeIfAbsent(index, k -> new ArrayList<>()).add(info);
        }
        // 为简化，不填充随机值（实际应填充空槽）
        return new HiddenCiphertext(revCt.components, revCt.C, revCt.C_tilde, HT, userId, timestamp);
    }

    // ==================== 内部类 ====================
    public static class PrivateKey {
        public String userId;
        public Element K, Kp;
        public Map<String, Element> Kc;
        public PrivateKey(String uid, Element K, Element Kp, Map<String, Element> Kc) {
            this.userId = uid; this.K = K; this.Kp = Kp; this.Kc = Kc;
        }
    }

    public static class CipherComponent {
        public Element Ci, Cip;
        public String attr;
        public CipherComponent(Element ci, Element cip, String attr) {
            this.Ci = ci; this.Cip = cip; this.attr = attr;
        }
    }

    public static class Ciphertext {
        public List<CipherComponent> components;
        public Element C, C_tilde;
        public Element[][] M;
        public Map<Integer, String> rho;
        public Ciphertext(List<CipherComponent> comps, Element c, Element ct, Element[][] m, Map<Integer, String> r) {
            this.components = comps; this.C = c; this.C_tilde = ct; this.M = m; this.rho = r;
        }
    }

    public static class RevokedCiphertext {
        public List<CipherComponent> components;
        public Element C, C_tilde;
        public Element[][] M;
        public Map<Integer, String> rho;
        public RevokedCiphertext(List<CipherComponent> comps, Element c, Element ct, Element[][] m, Map<Integer, String> r) {
            this.components = comps; this.C = c; this.C_tilde = ct; this.M = m; this.rho = r;
        }
    }

    public static class HiddenCiphertext {
        public List<CipherComponent> components;
        public Element C, C_tilde;
        public Map<Integer, List<RowInfo>> HT;
        public String userId, timestamp;
        public HiddenCiphertext(List<CipherComponent> comps, Element c, Element ct, Map<Integer, List<RowInfo>> ht, String uid, String ts) {
            this.components = comps; this.C = c; this.C_tilde = ct; this.HT = ht; this.userId = uid; this.timestamp = ts;
        }
    }

    public static class RowInfo {
        public int rowIndex;
        public Element[] rowVector;
        public RowInfo(int idx, Element[] vec) {
            this.rowIndex = idx; this.rowVector = vec;
        }
    }

    // ==================== 演示 ====================
    public static void main(String[] args) throws Exception {
        CPABEWithRevocationAndHiding scheme = new CPABEWithRevocationAndHiding();

        // 1. 用户注册，拥有 police 和 emergency 属性
        Set<String> userAttrs = new HashSet<>(Arrays.asList("police", "emergency"));
        String userId = "sp1";
        PrivateKey privKey = scheme.keyGen(userId, userAttrs);

        // 2. 构造访问策略 (police AND emergency)
        int l = 2;
        Element[][] M = new Element[2][l];
        for (int i = 0; i < 2; i++)
            for (int j = 0; j < l; j++)
                M[i][j] = scheme.Zr.newZeroElement();
        M[0][0] = scheme.Zr.newOneElement();                     // 行1: (1,0)
        M[1][0] = scheme.Zr.newOneElement();                     // 行2: (1,1)
        M[1][1] = scheme.Zr.newOneElement();
        Map<Integer, String> rho = new HashMap<>();
        rho.put(1, "police");
        rho.put(2, "emergency");

        String plaintext = "Emergency vehicle location";
        Ciphertext ct = scheme.encrypt(plaintext, M, rho);
        System.out.println("原始密文生成，行数: " + ct.components.size());

        // 3. 模拟属性撤销：用户失去 "police" 属性
        scheme.userAttributeTable.get(userId).put("police", false);
        System.out.println("用户 " + userId + " 的 police 属性已被撤销");

        // 4. TA执行撤销算法
        RevokedCiphertext revCt = scheme.attributeRevoke(ct, userId);
        System.out.println("撤销后剩余行数: " + revCt.components.size());

        // 5. TA执行策略隐藏
        String timestamp = String.valueOf(System.currentTimeMillis());
        HiddenCiphertext hiddenCt = scheme.policyStructureHiding(revCt, userId, timestamp);
        System.out.println("策略隐藏完成，HT大小: " + hiddenCt.HT.size());

        // 输出HT中的索引分布（演示）
        for (Map.Entry<Integer, List<RowInfo>> entry : hiddenCt.HT.entrySet()) {
            System.out.println("索引 " + entry.getKey() + " -> 存储行号: " +
                    entry.getValue().stream().map(info -> String.valueOf(info.rowIndex)).reduce((a,b)->a+","+b).orElse(""));
        }
    }
}