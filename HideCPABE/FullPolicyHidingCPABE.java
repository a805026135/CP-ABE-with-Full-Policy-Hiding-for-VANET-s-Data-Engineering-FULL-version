package cn.edu.buaa.crypto.HideCPABE;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class FullPolicyHidingCPABE {
    // 双线性群参数
    private Pairing pairing;
    private Field G1, GT, Zr;
    private Element g;          // G1的生成元
    private Element alpha, beta; // 主密钥成分
    private Element g_alpha;    // g^alpha
    private Element egg_beta;   // e(g,g)^beta

    // 哈希函数
    private MessageDigest sha256;

    // 用户属性表 TB (模拟)
    private Map<String, Map<String, Boolean>> userAttributeTable = new HashMap<>();

    // 哈希链表 HT (用于策略隐藏)
    private Map<Integer, List<RowInfo>> hashTable = new HashMap<>();

    // 辅助类：存储矩阵行信息
    static class RowInfo {
        int rowIndex;
        Element[] rowVector; // 实际存储 M[i][:]
        public RowInfo(int idx, Element[] vec) {
            this.rowIndex = idx;
            this.rowVector = vec;
        }
    }

    public FullPolicyHidingCPABE() throws NoSuchAlgorithmException {
        // 初始化JPBC Type A配对
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing("a.properties"); // 需要提供参数文件
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
        byte[] hash = sha256.digest(input.getBytes(StandardCharsets.UTF_8));
        // 简化为从哈希值派生群元素
        BigInteger h = new BigInteger(1, hash).mod(Zr.getOrder());
        return g.powZn(Zr.newElement(h)).getImmutable();
    }

    // ========== 1. 密钥生成 ==========
    public PrivateKey keyGen(String userId, Set<String> attrs) {
        Element t = Zr.newRandomElement(); // 每个用户随机t
        Element K = g.powZn(beta).mul(g_alpha.powZn(t)).getImmutable();
        Element Kp = g.powZn(t).getImmutable();
        Map<String, Element> Kc = new HashMap<>();
        for (String attr : attrs) {
            String hiddenAttr = hashToZr(attr).toString(); // H3(c)
            Element H1 = hashToG1(hiddenAttr);
            Kc.put(attr, H1.powZn(t).getImmutable());
        }
        // 记录用户属性到TB表
        userAttributeTable.putIfAbsent(userId, new HashMap<>());
        for (String attr : attrs) {
            userAttributeTable.get(userId).put(attr, true);
        }
        return new PrivateKey(userId, K, Kp, Kc);
    }

    // ========== 2. 加密 (车辆生成原始密文) ==========
    // 使用LSSS访问结构 (M, rho)
    public Ciphertext encrypt(String message, Element[][] M, Map<Integer, String> rho) {
        int n = M.length;   // 行数
        int l = M[0].length; // 列数
        // 随机秘密向量 v = (s, v2,..., vl)
        Element[] v = new Element[l];
        v[0] = Zr.newRandomElement(); // s
        for (int i = 1; i < l; i++) v[i] = Zr.newRandomElement();
        // 计算每个行对应的秘密份额 lambda_i = M_i · v
        Element[] lambda = new Element[n];
        for (int i = 0; i < n; i++) {
            lambda[i] = Zr.newZeroElement();
            for (int j = 0; j < l; j++) {
                lambda[i].add(M[i][j].duplicate().mul(v[j]));
            }
            lambda[i] = lambda[i].getImmutable();
        }
        // 随机 r_i
        Element[] r = new Element[n];
        for (int i = 0; i < n; i++) r[i] = Zr.newRandomElement();

        Element C = g.powZn(v[0]).getImmutable(); // C = g^s
        // 消息加密: \tilde{C} = m * e(g,g)^{s*beta}
        Element egg_s_beta = egg_beta.powZn(v[0]);
        Element mElement = Zr.newElement(new BigInteger(message.getBytes())).getImmutable(); // 简化: 消息转为Zr
        Element C_tilde = mElement.duplicate().mul(egg_s_beta).getImmutable();

        List<CipherComponent> comps = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String attr = rho.get(i+1); // 假设行号从1开始
            String hiddenAttr = hashToZr(attr).toString();
            Element H1 = hashToG1(hiddenAttr);
            Element Ci = g_alpha.powZn(lambda[i]).mul(H1.powZn(r[i]).invert()).getImmutable();
            Element Cip = g.powZn(r[i]).getImmutable();
            comps.add(new CipherComponent(Ci, Cip, attr)); // 保存原始属性用于后续撤销
        }
        return new Ciphertext(comps, C, C_tilde, M, rho);
    }

    // ========== 3. 属性撤销和策略隐藏 (TA执行) ==========
    public CiphertextWithHiddenPolicy attributeRevokeAndHide(Ciphertext ct, String userId) {
        // 获取用户属性表
        Map<String, Boolean> userAttrs = userAttributeTable.getOrDefault(userId, new HashMap<>());
        List<CipherComponent> newComps = new ArrayList<>();
        List<Integer> remainingRows = new ArrayList<>();
        Element[][] newM = null;
        Map<Integer, String> newRho = new HashMap<>();

        // 根据用户属性撤销: 如果用户没有某属性，则删除对应的行
        for (int i = 0; i < ct.components.size(); i++) {
            CipherComponent comp = ct.components.get(i);
            String attr = comp.attr;
            if (userAttrs.getOrDefault(attr, false)) {
                newComps.add(comp);
                remainingRows.add(i);
            }
        }
        int nf = newComps.size();
        // 重建访问矩阵和rho
        newM = new Element[nf][ct.M[0].length];
        for (int j = 0; j < nf; j++) {
            int origIdx = remainingRows.get(j);
            newM[j] = ct.M[origIdx];
            newRho.put(j+1, ct.rho.get(origIdx+1));
        }

        // 策略隐藏: 构建哈希表 HT
        hashTable.clear();
        String id = userId;
        String timestamp = String.valueOf(System.currentTimeMillis());
        for (int i = 0; i < nf; i++) {
            String attr = newRho.get(i+1);
            String key = hashToZr(attr + id + timestamp).toString(); // H2(attr, ID, t)
            int index = Math.abs(key.hashCode()) % 1024; // 简化的哈希表索引
            RowInfo info = new RowInfo(i+1, newM[i]);
            hashTable.computeIfAbsent(index, k -> new ArrayList<>()).add(info);
        }
        // 返回隐藏后的密文 (只保留HT和相关密文组件)
        return new CiphertextWithHiddenPolicy(newComps, ct.C, ct.C_tilde, hashTable, id, timestamp);
    }

    // ========== 4. 外包解密 ==========
    // 用户生成外包密钥
    public OutsourcingKey genOutsourcingKey(PrivateKey privKey) {
        Element z = Zr.newRandomElement(); // ODK
        Element Ko = privKey.K.powZn(z).getImmutable();
        Element Kop = privKey.Kp.powZn(z).getImmutable();
        Map<String, Element> Koc = new HashMap<>();
        for (Map.Entry<String, Element> e : privKey.Kc.entrySet()) {
            Koc.put(e.getKey(), e.getValue().powZn(z).getImmutable());
        }
        return new OutsourcingKey(z, Ko, Kop, Koc);
    }

    // 云服务器部分解密
    public Element cloudDecrypt(CiphertextWithHiddenPolicy ct, OutsourcingKey ok, Set<String> userAttrs) {
        // 从HT中恢复出用户属性对应的矩阵行
        List<Integer> validRows = new ArrayList<>();
        List<Element> omegaList = new ArrayList<>();
        // 简化的恢复过程: 根据用户属性查找HT中的行
        for (String attr : userAttrs) {
            String key = hashToZr(attr + ct.id + ct.timestamp).toString();
            int idx = Math.abs(key.hashCode()) % 1024;
            if (hashTable.containsKey(idx)) {
                for (RowInfo info : hashTable.get(idx)) {
                    validRows.add(info.rowIndex);
                    // 这里需要求解恢复向量omega，简化：假设单属性满足策略时omega=1
                    omegaList.add(Zr.newOneElement());
                }
            }
        }
        // 计算E = e(C, Ko) / prod_i ( e(K_{o,rho(i)}, Ci') * e(Ko', Ci) )^{omega_i}
        Element numerator = pairing.pairing(ct.C, ok.Ko);
        Element denominator = GT.newOneElement();
        for (int i = 0; i < validRows.size(); i++) {
            int row = validRows.get(i) - 1;
            CipherComponent comp = ct.components.get(row);
            String attr = comp.attr;
            Element Koc = ok.Koc.get(attr);
            Element term1 = pairing.pairing(Koc, comp.Cip);
            Element term2 = pairing.pairing(ok.Kop, comp.Ci);
            Element factor = term1.mul(term2).powZn(omegaList.get(i));
            denominator.mul(factor);
        }
        Element E = numerator.mul(denominator.invert()).getImmutable();
        return E;
    }

    // 用户最终解密
    public String finalDecrypt(CiphertextWithHiddenPolicy ct, OutsourcingKey ok, Element E) {
        Element mElement = ct.C_tilde.duplicate().mul(E.powZn(ok.z.invert()).invert()).getImmutable();
        // 将Zr元素转换回消息字符串 (简化)
        byte[] msgBytes = mElement.toBytes();
        return new String(msgBytes, StandardCharsets.UTF_8);
    }

    // ========== 辅助类 ==========
    static class PrivateKey {
        String userId; Element K, Kp; Map<String, Element> Kc;
        PrivateKey(String uid, Element K, Element Kp, Map<String, Element> Kc) {
            this.userId = uid; this.K = K; this.Kp = Kp; this.Kc = Kc;
        }
    }
    static class CipherComponent {
        Element Ci, Cip; String attr;
        CipherComponent(Element ci, Element cip, String a) { Ci=ci; Cip=cip; attr=a; }
    }
    static class Ciphertext {
        List<CipherComponent> components; Element C, C_tilde; Element[][] M; Map<Integer, String> rho;
        Ciphertext(List<CipherComponent> comps, Element c, Element ct, Element[][] m, Map<Integer, String> r) {
            components=comps; C=c; C_tilde=ct; M=m; rho=r;
        }
    }
    static class CiphertextWithHiddenPolicy {
        List<CipherComponent> components; Element C, C_tilde; Map<Integer, List<RowInfo>> HT; String id, timestamp;
        CiphertextWithHiddenPolicy(List<CipherComponent> comps, Element c, Element ct, Map<Integer, List<RowInfo>> ht, String id, String ts) {
            components=comps; C=c; C_tilde=ct; HT=ht; this.id=id; timestamp=ts;
        }
    }
    static class OutsourcingKey {
        Element z, Ko, Kop; Map<String, Element> Koc;
        OutsourcingKey(Element z, Element ko, Element kop, Map<String, Element> koc) {
            this.z=z; Ko=ko; Kop=kop; Koc=koc;
        }
    }

    // 演示流程
    public static void main(String[] args) throws Exception {
        FullPolicyHidingCPABE scheme = new FullPolicyHidingCPABE();
        // 用户属性
        Set<String> userAttrs = new HashSet<>(Arrays.asList("police", "emergency"));
        String userId = "sp1";
        PrivateKey privKey = scheme.keyGen(userId, userAttrs);

        // 定义访问策略: (police AND emergency)  OR (ambulance)
        // 构造LSSS矩阵 (简单示例: 2行，分别对应 police 和 emergency，策略为AND)
        int l = 2; // 列数
        Element[][] M = new Element[2][l];
        for (int i=0;i<2;i++) for(int j=0;j<l;j++) M[i][j] = scheme.Zr.newZeroElement();
        M[0][0] = scheme.Zr.newOneElement(); // 第一行: (1,0)
        M[1][0] = scheme.Zr.newOneElement(); M[1][1] = scheme.Zr.newOneElement(); // 第二行: (1,1)
        Map<Integer, String> rho = new HashMap<>();
        rho.put(1, "police");
        rho.put(2, "emergency");

        String plaintext = "Emergency vehicle data";
        Ciphertext ct = scheme.encrypt(plaintext, M, rho);

        // TA执行撤销和策略隐藏
        CiphertextWithHiddenPolicy hiddenCt = scheme.attributeRevokeAndHide(ct, userId);

        // 用户生成外包密钥并请求云解密
        OutsourcingKey ok = scheme.genOutsourcingKey(privKey);
        Element E = scheme.cloudDecrypt(hiddenCt, ok, userAttrs);
        String decrypted = scheme.finalDecrypt(hiddenCt, ok, E);

        System.out.println("Decrypted: " + decrypted);
    }
}